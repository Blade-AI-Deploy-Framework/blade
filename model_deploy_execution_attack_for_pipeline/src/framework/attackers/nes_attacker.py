import numpy as np
import cv2
import uuid
from concurrent.futures import ProcessPoolExecutor
import os

from ..base_attack import BaseAttack, _evaluate_mutation_on_host_for_pool

class NesAttack(BaseAttack):
    @staticmethod
    def add_attack_args(parser):
        nes_group = parser.add_argument_group("NES Attack Parameters")
        nes_group.add_argument("--population-size", type=int, default=200, help="Population size for NES. Must be even.")
        nes_group.add_argument("--sigma", type=float, default=0.15, help="Sigma for NES.")
        
        gradient_group = parser.add_argument_group("Gradient Estimation Tuning")
        gradient_group.add_argument("--disable-fitness-shaping", dest="enable_fitness_shaping", action="store_false", help="Disable fitness shaping (ranking), which is enabled by default.")
        parser.set_defaults(enable_fitness_shaping=True)

        optimizer_group = parser.add_argument_group("Optimizer Settings")
        optimizer_group.add_argument("--adam-beta1", type=float, default=0.9, help="Adam optimizer beta1 parameter.")
        optimizer_group.add_argument("--adam-beta2", type=float, default=0.999, help="Adam optimizer beta2 parameter.")
        optimizer_group.add_argument("--adam-epsilon", type=float, default=1e-8, help="Adam optimizer epsilon parameter.")

    def setup_attack(self):
        self.attack_image_for_nes = self.attack_image.copy()
        self.m = np.zeros_like(self.attack_image_for_nes, dtype=np.float32)
        self.v = np.zeros_like(self.attack_image_for_nes, dtype=np.float32)
        self.adam_step_counter = 0

    def get_attack_candidate(self, iteration):
        dynamic_weights = {addr: state["dynamic_weight"] for addr, state in self.hooks_attack_state.items()}
        
        grad = self._estimate_gradient_nes(self.attack_image_for_nes, dynamic_weights)
        queries_made = self.args.population_size

        self.adam_step_counter += 1
        t = self.adam_step_counter
        self.m = self.args.adam_beta1 * self.m + (1 - self.args.adam_beta1) * grad
        self.v = self.args.adam_beta2 * self.v + (1 - self.args.adam_beta2) * (grad ** 2)
        m_hat = self.m / (1 - self.args.adam_beta1 ** t)
        v_hat = self.v / (1 - self.args.adam_beta2 ** t)
        update_step = self.current_lr * m_hat / (np.sqrt(v_hat + self.args.adam_epsilon))
        
        self.attack_image_for_nes -= update_step

        perturbation = np.clip(self.attack_image_for_nes - self.original_image_float, -self.args.l_inf_norm, self.args.l_inf_norm)
        candidate_image = np.clip(self.original_image_float + perturbation, 0, 255)

        return candidate_image, queries_made
    
    def accept_candidate(self, candidate_image, loss, is_successful, hook_diagnostics):
        self.attack_image = candidate_image
        self.attack_image_for_nes = candidate_image.copy()

    def _estimate_gradient_nes(self, image, dynamic_weights):
        run_id = uuid.uuid4().hex[:12]
        image_shape = image.shape
        pop_size = self.args.population_size
        sigma = self.args.sigma
        
        if pop_size % 2 != 0:
            raise ValueError(f"Population size must be even. Got {pop_size}.")

        half_pop_size = pop_size // 2
        
        noise_vectors = [np.random.randn(*image_shape) for _ in range(half_pop_size)]
        mutations_data_for_writing = []
        tasks = []

        for i, noise in enumerate(noise_vectors):
            mutant_pos = np.clip(image + sigma * noise, 0, 255)
            mutant_neg = np.clip(image - sigma * noise, 0, 255)

            _, encoded_pos = cv2.imencode(".png", cv2.cvtColor(mutant_pos.astype(np.uint8), cv2.COLOR_RGB2BGR))
            _, encoded_neg = cv2.imencode(".png", cv2.cvtColor(mutant_neg.astype(np.uint8), cv2.COLOR_RGB2BGR))

            fname_pos = f"temp_nes_{run_id}_{i}_pos.png"
            fname_neg = f"temp_nes_{run_id}_{i}_neg.png"
            
            mutations_data_for_writing.extend([(fname_pos, encoded_pos.tobytes()), (fname_neg, encoded_neg.tobytes())])

            path_pos = os.path.join(self.workdir, fname_pos)
            path_neg = os.path.join(self.workdir, fname_neg)
            tasks.extend([
                (path_pos, self.hook_config, dynamic_weights, vars(self.args)),
                (path_neg, self.hook_config, dynamic_weights, vars(self.args))
            ])

        try:
            self._write_multiple_files_to_host(mutations_data_for_writing, self.workdir)

            print(f"--- Evaluating {pop_size} mutations with {self.args.workers} workers ---")
            losses = np.zeros(pop_size)
            with ProcessPoolExecutor(max_workers=self.args.workers) as executor:
                results = executor.map(_evaluate_mutation_on_host_for_pool, tasks)
                for i, loss in enumerate(results):
                    losses[i] = loss
            
        finally:
            cleanup_pattern = os.path.join(self.workdir, f"temp_nes_{run_id}_*.png")
            self._remove_files_on_host_batch(cleanup_pattern)

        if np.inf in losses:
            non_inf_max = np.max(losses[losses != np.inf], initial=0)
            losses[losses == np.inf] = non_inf_max + 1

        if self.args.enable_fitness_shaping:
            ranks = np.empty_like(losses, dtype=int)
            ranks[np.argsort(losses)] = np.arange(pop_size)
            shaped_losses = (ranks / (pop_size - 1)) - 0.5
        else:
            shaped_losses = losses

        gradient = np.zeros_like(image, dtype=np.float32)
        for i in range(half_pop_size):
            loss_pos = shaped_losses[2 * i]
            loss_neg = shaped_losses[2 * i + 1]
            gradient += (loss_pos - loss_neg) * noise_vectors[i]

        gradient /= (pop_size * sigma)
        
        grad_norm = np.linalg.norm(gradient)
        if grad_norm > 1e-8:
            gradient /= grad_norm
        
        return gradient
