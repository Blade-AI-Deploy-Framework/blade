import numpy as np
import cv2

from ..base_attack import BaseAttack

class SquareAttack(BaseAttack):
    @staticmethod
    def add_attack_args(parser):
        square_group = parser.add_argument_group("Square Attack Parameters")
        square_group.add_argument("--p-init", type=float, default=0.1, help="Initial fraction of features to perturb.")
        # Note: Iterations for Square Attack correspond to queries.
        # Learning rate and optimizer args are not used.

    def setup_attack(self):
        # Initialize with a random perturbation
        init_perturb = np.random.choice([-self.args.l_inf_norm, self.args.l_inf_norm], size=self.original_image_float.shape)
        self.attack_image = np.clip(self.original_image_float + init_perturb, 0, 255)

        # Initial evaluation is done in the base class, so `best_loss_so_far` is already set.
        print(f"Square attack initialized. Starting loss: {self.best_loss_so_far:.6f}")

    def get_attack_candidate(self, iteration):
        h, w, c = self.original_image_float.shape
        n_features = c * h * w

        # Determine patch size for this iteration
        p = self._p_selection(self.args.p_init, iteration, self.args.iterations)
        s = int(round(np.sqrt(p * n_features / c)))
        s = min(max(s, 1), h - 1)

        # Choose random location for the patch
        center_h = np.random.randint(0, h - s)
        center_w = np.random.randint(0, w - s)
        
        # Create a new perturbation attempt
        current_perturbation = self.attack_image - self.original_image_float
        new_perturbation = current_perturbation.copy()
        
        # Generate random sign flips for the patch
        rand_signs = np.random.choice([-1, 1], size=(c,)) * self.args.l_inf_norm
        new_perturbation[center_h:center_h+s, center_w:center_w+s, :] = rand_signs

        candidate_image = np.clip(self.original_image_float + new_perturbation, 0, 255)
        
        # Square attack makes one query to generate one candidate
        return candidate_image, 0 # The query is made in the main loop

    def accept_candidate(self, candidate_image, loss, is_successful, hook_diagnostics):
        # Accept the candidate only if it improves the loss
        if loss < self.best_loss_so_far:
            self.attack_image = candidate_image
            # best_loss_so_far will be updated in the main loop's _save_images call
        
    def _p_selection(self, p_init, it, n_iters):
        """ Piece-wise constant schedule for p (the fraction of pixels changed on every iteration). """
        it = int(it / n_iters * 10000)

        if 10 < it <= 50: p = p_init / 2
        elif 50 < it <= 200: p = p_init / 4
        elif 200 < it <= 500: p = p_init / 8
        elif 500 < it <= 1000: p = p_init / 16
        elif 1000 < it <= 2000: p = p_init / 32
        elif 2000 < it <= 4000: p = p_init / 64
        elif 4000 < it <= 6000: p = p_init / 128
        elif 6000 < it <= 8000: p = p_init / 256
        elif 8000 < it <= 10000: p = p_init / 512
        else: p = p_init
        return p
