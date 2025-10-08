import numpy as np
import cv2
import uuid
from concurrent.futures import ProcessPoolExecutor
import os

from ..base_attack import BaseAttack, _evaluate_mutation_on_host_for_pool

class BanditAttack(BaseAttack):
    @staticmethod
    def add_attack_args(parser):
        bandit_group = parser.add_argument_group("Bandit Attack Parameters")
        bandit_group.add_argument("--fd-eta", type=float, default=0.1, help="Finite difference step size.")
        bandit_group.add_argument("--prior-exploration", type=float, default=0.1, help="Exploration factor for the prior.")
        bandit_group.add_argument("--prior-size", type=int, default=32, help="The side length of the square low-dimensional prior.")
        bandit_group.add_argument("--prior-lr", type=float, default=0.1, help="Learning rate for updating the prior.")
        
        optimizer_group = parser.add_argument_group("Optimizer Settings")
        optimizer_group.add_argument("--adam-beta1", type=float, default=0.9, help="Adam optimizer beta1 parameter.")
        optimizer_group.add_argument("--adam-beta2", type=float, default=0.999, help="Adam optimizer beta2 parameter.")
        optimizer_group.add_argument("--adam-epsilon", type=float, default=1e-8, help="Adam optimizer epsilon parameter.")

    def setup_attack(self):
        self.attack_image_for_bandit = self.attack_image.copy()
        
        # Initialize prior for Bandit attack
        prior_shape = (self.args.prior_size, self.args.prior_size, 3) # H, W, C
        self.prior = np.zeros(prior_shape, dtype=np.float32)

        self.m = np.zeros_like(self.attack_image_for_bandit, dtype=np.float32)
        self.v = np.zeros_like(self.attack_image_for_bandit, dtype=np.float32)
        self.adam_step_counter = 0

    def get_attack_candidate(self, iteration):
        dynamic_weights = {addr: state["dynamic_weight"] for addr, state in self.hooks_attack_state.items()}
        
        grad, self.prior = self._estimate_gradient_bandit(self.attack_image_for_bandit, self.prior, dynamic_weights)
        queries_made = 2

        self.adam_step_counter += 1
        t = self.adam_step_counter
        self.m = self.args.adam_beta1 * self.m + (1 - self.args.adam_beta1) * grad
        self.v = self.args.adam_beta2 * self.v + (1 - self.args.adam_beta2) * (grad ** 2)
        m_hat = self.m / (1 - self.args.adam_beta1 ** t)
        v_hat = self.v / (1 - self.args.adam_beta2 ** t)
        update_step = self.current_lr * m_hat / (np.sqrt(v_hat + self.args.adam_epsilon))
        
        self.attack_image_for_bandit -= update_step

        perturbation = np.clip(self.attack_image_for_bandit - self.original_image_float, -self.args.l_inf_norm, self.args.l_inf_norm)
        candidate_image = np.clip(self.original_image_float + perturbation, 0, 255)

        return candidate_image, queries_made
    
    def accept_candidate(self, candidate_image, loss, is_successful, hook_diagnostics):
        # Gradient-based methods always accept the new image
        self.attack_image = candidate_image
        self.attack_image_for_bandit = candidate_image.copy()

    def _upsample(self, source_array, target_height, target_width):
        return cv2.resize(source_array, (target_width, target_height), interpolation=cv2.INTER_LINEAR)

    def _estimate_gradient_bandit(self, image, prior, dynamic_weights):
        run_id = uuid.uuid4().hex[:12]
        h, w, c = image.shape
        prior_shape = (self.args.prior_size, self.args.prior_size, c)
        
        exp_noise = np.random.randn(*prior_shape)
        
        q1_prior = prior + self.args.prior_exploration * exp_noise
        q2_prior = prior - self.args.prior_exploration * exp_noise
        
        q1_full = self._upsample(q1_prior, h, w)
        q2_full = self._upsample(q2_prior, h, w)
        
        mutant1 = np.clip(image + self.args.fd_eta * q1_full, 0, 255)
        mutant2 = np.clip(image + self.args.fd_eta * q2_full, 0, 255)

        _, encoded1 = cv2.imencode(".png", cv2.cvtColor(mutant1.astype(np.uint8), cv2.COLOR_RGB2BGR))
        _, encoded2 = cv2.imencode(".png", cv2.cvtColor(mutant2.astype(np.uint8), cv2.COLOR_RGB2BGR))

        fname1 = f"temp_bandit_{run_id}_1.png"
        fname2 = f"temp_bandit_{run_id}_2.png"
        path1 = os.path.join(self.workdir, fname1)
        path2 = os.path.join(self.workdir, fname2)

        mutations_data = [(fname1, encoded1.tobytes()), (fname2, encoded2.tobytes())]
        tasks = [
            (path1, self.hook_config, dynamic_weights, vars(self.args)),
            (path2, self.hook_config, dynamic_weights, vars(self.args))
        ]

        try:
            self._write_multiple_files_to_host(mutations_data, self.workdir)

            losses = np.zeros(2)
            with ProcessPoolExecutor(max_workers=self.args.workers) as executor:
                results = executor.map(_evaluate_mutation_on_host_for_pool, tasks)
                for i, loss in enumerate(results):
                    losses[i] = loss
        finally:
            cleanup_pattern = os.path.join(self.workdir, f"temp_bandit_{run_id}_*.png")
            self._remove_files_on_host_batch(cleanup_pattern)

        l1, l2 = losses[0], losses[1]
        
        est_deriv = (l1 - l2) / (self.args.fd_eta * self.args.prior_exploration)
        est_grad_prior = est_deriv * exp_noise
        
        updated_prior = prior - self.args.prior_lr * np.sign(est_grad_prior)
        
        gradient_full = self._upsample(updated_prior, h, w)
        grad_norm = np.linalg.norm(gradient_full)
        if grad_norm > 1e-8:
            gradient_full /= grad_norm
        
        return gradient_full, updated_prior
