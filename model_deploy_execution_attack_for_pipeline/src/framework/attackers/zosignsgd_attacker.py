import numpy as np
import cv2
import uuid
from concurrent.futures import ProcessPoolExecutor
import os

from ..base_attack import BaseAttack, _evaluate_mutation_on_host_for_pool

class ZosignsgdAttack(BaseAttack):
    @staticmethod
    def add_attack_args(parser):
        zo_group = parser.add_argument_group("ZO-Sign-SGD Parameters")
        zo_group.add_argument("--num-queries", "-q", type=int, default=100, help="Number of random directions to query per iteration.")
        zo_group.add_argument("--fd-eta", type=float, default=0.15, help="Finite difference step size (exploration magnitude).")

    def setup_attack(self):
        self.attack_image_for_zo = self.attack_image.copy()
        # ZO-Sign-SGD does not use Adam, so no m, v state needed.

    def get_attack_candidate(self, iteration):
        dynamic_weights = {addr: state["dynamic_weight"] for addr, state in self.hooks_attack_state.items()}
        
        grad = self._estimate_gradient_zosignsgd(self.attack_image_for_zo, dynamic_weights)
        queries_made = self.args.num_queries + 1 # +1 for the base image evaluation

        update_step = self.current_lr * np.sign(grad)
        self.attack_image_for_zo -= update_step

        perturbation = np.clip(self.attack_image_for_zo - self.original_image_float, -self.args.l_inf_norm, self.args.l_inf_norm)
        candidate_image = np.clip(self.original_image_float + perturbation, 0, 255)

        return candidate_image, queries_made
    
    def accept_candidate(self, candidate_image, loss, is_successful, hook_diagnostics):
        self.attack_image = candidate_image
        self.attack_image_for_zo = candidate_image.copy()

    def _estimate_gradient_zosignsgd(self, image, dynamic_weights):
        run_id = uuid.uuid4().hex[:12]
        image_shape = image.shape
        q = self.args.num_queries
        fd_eta = self.args.fd_eta
        
        _, encoded_original = cv2.imencode(".png", cv2.cvtColor(image.astype(np.uint8), cv2.COLOR_RGB2BGR))
        base_image_path = os.path.join(self.workdir, f"temp_zo_{run_id}_base.png")
        self._write_multiple_files_to_host([(f"temp_zo_{run_id}_base.png", encoded_original.tobytes())], self.workdir)
        
        base_loss = _evaluate_mutation_on_host_for_pool((base_image_path, self.hook_config, dynamic_weights, vars(self.args)))
        os.remove(base_image_path)

        noise_vectors = [np.random.randn(*image_shape) for _ in range(q)]
        mutations_data, tasks = [], []

        for i, noise in enumerate(noise_vectors):
            mutant_pos = np.clip(image + fd_eta * noise, 0, 255)
            _, encoded_pos = cv2.imencode(".png", cv2.cvtColor(mutant_pos.astype(np.uint8), cv2.COLOR_RGB2BGR))
            fname_pos = f"temp_zo_{run_id}_{i}_pos.png"
            mutations_data.append((fname_pos, encoded_pos.tobytes()))
            path_pos = os.path.join(self.workdir, fname_pos)
            tasks.append((path_pos, self.hook_config, dynamic_weights, vars(self.args)))

        try:
            self._write_multiple_files_to_host(mutations_data, self.workdir)

            losses = np.zeros(q)
            with ProcessPoolExecutor(max_workers=self.args.workers) as executor:
                results = executor.map(_evaluate_mutation_on_host_for_pool, tasks)
                for i, loss in enumerate(results):
                    losses[i] = loss
        finally:
            self._remove_files_on_host_batch(os.path.join(self.workdir, f"temp_zo_{run_id}_*.png"))

        gradient = np.zeros_like(image, dtype=np.float32)
        for i in range(q):
            gradient += (losses[i] - base_loss) * noise_vectors[i]

        return gradient / (q * fd_eta)
