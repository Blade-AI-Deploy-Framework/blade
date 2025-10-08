import numpy as np
import cv2
import uuid
from concurrent.futures import ProcessPoolExecutor
import os
from collections import deque

from ..base_attack import BaseAttack, _evaluate_mutation_on_host_for_pool

class SpsaAttack(BaseAttack):
    @staticmethod
    def add_attack_args(parser):
        spsa_group = parser.add_argument_group("SPSA Settings")
        spsa_group.add_argument("--spsa-grad-samples", type=int, default=32, help="Number of gradient samples to average for SPSA.")
        spsa_group.add_argument("--spsa-c", type=float, default=0.1, help="SPSA parameter c for perturbation size.")
        spsa_group.add_argument("--spsa-c-gamma", type=float, default=0.101, help="SPSA parameter gamma for decaying c.")
        spsa_group.add_argument("--spsa-A", type=float, default=20.0, help="SPSA parameter A for stability.")

        optimizer_group = parser.add_argument_group("Optimizer Settings")
        stabilization_group = optimizer_group.add_mutually_exclusive_group()
        stabilization_group.add_argument("--use-signed-grad", action="store_true", help="Use the sign of the gradient for the update step.")
        stabilization_group.add_argument("--use-gradient-normalization", action="store_true", help="Use L2 normalization on the gradient.")
        optimizer_group.add_argument("--grad-smoothing-samples", type=int, default=1, help="Number of recent gradients to average for a smoother update. Set to 1 to disable.")
        optimizer_group.add_argument("--adam-beta1", type=float, default=0.9, help="Adam optimizer beta1 parameter.")
        optimizer_group.add_argument("--adam-beta2", type=float, default=0.999, help="Adam optimizer beta2 parameter.")
        optimizer_group.add_argument("--adam-epsilon", type=float, default=1e-8, help="Adam optimizer epsilon parameter.")
        
        perturbation_group = parser.add_argument_group("Perturbation Settings")
        perturbation_group.add_argument("--resize-dim", type=int, default=0, help="Resize perturbation to this dimension before applying. 0 to disable.")
        perturbation_group.add_argument("--attack-y-channel-only", action="store_true", help="Perform the attack on the Y (luminance) channel only.")

    def setup_attack(self):
        pert_shape = (self.attack_image.shape[0], self.attack_image.shape[1], 1) if self.args.attack_y_channel_only else self.attack_image.shape
        self.m = np.zeros(pert_shape, dtype=np.float32)
        self.v = np.zeros(pert_shape, dtype=np.float32)
        self.adam_step_counter = 0

        self.grad_history = None
        if self.args.grad_smoothing_samples > 1:
            self.grad_history = deque(maxlen=self.args.grad_smoothing_samples)

    def get_attack_candidate(self, iteration):
        dynamic_weights = {addr: state["dynamic_weight"] for addr, state in self.hooks_attack_state.items()}
        current_c = self.args.spsa_c / ((iteration + self.args.spsa_A) ** self.args.spsa_c_gamma)

        grad_raw = self._estimate_gradient_spsa(self.attack_image, dynamic_weights, current_c)
        queries_made = 2 * self.args.spsa_grad_samples

        grad = grad_raw
        if self.grad_history is not None:
            self.grad_history.append(grad_raw)
            grad = np.mean(list(self.grad_history), axis=0)

        if self.args.use_signed_grad:
            grad = np.sign(grad)
        elif self.args.use_gradient_normalization:
            grad_norm = np.linalg.norm(grad)
            if grad_norm > 1e-8: grad = grad / grad_norm
        
        self.adam_step_counter += 1
        t = self.adam_step_counter
        self.m = self.args.adam_beta1 * self.m + (1 - self.args.adam_beta1) * grad
        self.v = self.args.adam_beta2 * self.v + (1 - self.args.adam_beta2) * (grad ** 2)
        m_hat = self.m / (1 - self.args.adam_beta1 ** t)
        v_hat = self.v / (1 - self.args.adam_beta2 ** t)
        update_step = self.current_lr * m_hat / (np.sqrt(v_hat + self.args.adam_epsilon))
        
        candidate_image = self.attack_image.copy()
        if self.args.attack_y_channel_only:
            attack_image_yuv = cv2.cvtColor(candidate_image.astype(np.uint8), cv2.COLOR_RGB2YUV).astype(np.float32)
            attack_image_yuv[:, :, 0] -= np.squeeze(update_step, axis=-1)
            candidate_image = cv2.cvtColor(np.clip(attack_image_yuv, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB).astype(np.float32)
        else:
            candidate_image -= update_step

        perturbation = np.clip(candidate_image - self.original_image_float, -self.args.l_inf_norm, self.args.l_inf_norm)
        candidate_image = np.clip(self.original_image_float + perturbation, 0, 255)

        return candidate_image, queries_made

    def accept_candidate(self, candidate_image, loss, is_successful, hook_diagnostics):
        self.attack_image = candidate_image

    def _estimate_gradient_spsa(self, image, dynamic_weights, current_c):
        run_id = uuid.uuid4().hex[:12]
        image_shape = image.shape
        num_samples = self.args.spsa_grad_samples
        
        pert_shape = (image_shape[0], image_shape[1]) if self.args.attack_y_channel_only else image_shape
        resize_downsampled_shape = (self.args.resize_dim, self.args.resize_dim) if self.args.resize_dim > 0 and self.args.attack_y_channel_only else \
                                 (self.args.resize_dim, self.args.resize_dim, image_shape[2]) if self.args.resize_dim > 0 else None

        deltas = []
        for _ in range(num_samples):
            if self.args.resize_dim and self.args.resize_dim > 0:
                delta_low_dim = np.random.choice([-1, 1], size=resize_downsampled_shape).astype(np.float32)
                delta = cv2.resize(delta_low_dim, (image_shape[1], image_shape[0]), interpolation=cv2.INTER_NEAREST)
            else:
                delta = np.random.choice([-1, 1], size=pert_shape).astype(np.float32)
            
            if delta.ndim == 2: delta = np.expand_dims(delta, axis=-1)
            deltas.append(delta)

        mutations_data, tasks = [], []
        for i, delta in enumerate(deltas):
            if self.args.attack_y_channel_only:
                yuv_image = cv2.cvtColor(image.astype(np.uint8), cv2.COLOR_RGB2YUV).astype(np.float32)
                y_channel, delta_squeezed = yuv_image[:, :, 0], np.squeeze(delta, axis=-1)
                y_pos, y_neg = y_channel + current_c * delta_squeezed, y_channel - current_c * delta_squeezed
                
                yuv_pos = yuv_image.copy(); yuv_pos[:, :, 0] = y_pos
                mutant_pos = cv2.cvtColor(np.clip(yuv_pos, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB)
                yuv_neg = yuv_image.copy(); yuv_neg[:, :, 0] = y_neg
                mutant_neg = cv2.cvtColor(np.clip(yuv_neg, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB)
            else:
                mutant_pos = np.clip(image + current_c * delta, 0, 255)
                mutant_neg = np.clip(image - current_c * delta, 0, 255)

            _, encoded_pos = cv2.imencode(".png", cv2.cvtColor(mutant_pos.astype(np.uint8), cv2.COLOR_RGB2BGR))
            _, encoded_neg = cv2.imencode(".png", cv2.cvtColor(mutant_neg.astype(np.uint8), cv2.COLOR_RGB2BGR))
            
            fname_pos, fname_neg = f"temp_spsa_{run_id}_{i}_pos.png", f"temp_spsa_{run_id}_{i}_neg.png"
            mutations_data.extend([(fname_pos, encoded_pos.tobytes()), (fname_neg, encoded_neg.tobytes())])
            
            path_pos, path_neg = os.path.join(self.workdir, fname_pos), os.path.join(self.workdir, fname_neg)
            tasks.extend([(path_pos, self.hook_config, dynamic_weights, vars(self.args)), (path_neg, self.hook_config, dynamic_weights, vars(self.args))])

        try:
            self._write_multiple_files_to_host(mutations_data, self.workdir)
            losses = np.zeros(len(tasks))
            with ProcessPoolExecutor(max_workers=self.args.workers) as executor:
                results = executor.map(_evaluate_mutation_on_host_for_pool, tasks)
                for i, loss in enumerate(results): losses[i] = loss
        finally:
            self._remove_files_on_host_batch(os.path.join(self.workdir, f"temp_spsa_{run_id}_*.png"))

        grad_shape = (image_shape[0], image_shape[1], 1) if self.args.attack_y_channel_only else image_shape
        total_grads = np.zeros(grad_shape, dtype=np.float32)
        for i in range(num_samples):
            loss_pos, loss_neg = losses[2 * i], losses[2 * i + 1]
            if not (np.isinf(loss_pos) or np.isinf(loss_neg)):
                total_grads += deltas[i] * ((loss_pos - loss_neg) / (2 * current_c + 1e-10))
        
        return total_grads / num_samples
