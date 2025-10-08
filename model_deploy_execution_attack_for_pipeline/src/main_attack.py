import argparse
import sys

from framework.base_attack import BaseAttack
from framework.attackers.nes_attacker import NesAttack
from framework.attackers.spsa_attacker import SpsaAttack
from framework.attackers.bandit_attacker import BanditAttack
from framework.attackers.square_attacker import SquareAttack
from framework.attackers.zosignsgd_attacker import ZosignsgdAttack

def main():
    # A pre-parser to get the attack type first
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--attack-type", required=True, choices=['nes', 'spsa', 'bandit', 'square', 'zosignsgd'], help="The attack algorithm to use.")
    args, _ = pre_parser.parse_known_args()

    attack_map = {
        'nes': NesAttack,
        'spsa': SpsaAttack,
        'bandit': BanditAttack,
        'square': SquareAttack,
        'zosignsgd': ZosignsgdAttack
    }

    AttackClass = attack_map.get(args.attack_type)
    if not AttackClass:
        print(f"Error: Unknown attack type '{args.attack_type}'")
        sys.exit(1)

    # Main parser
    parser = argparse.ArgumentParser(description=f"Pluggable Adversarial Attack Framework: {args.attack_type.upper()} Attack")
    
    # Add attack-type argument again for completeness in --help
    parser.add_argument("--attack-type", required=True, choices=attack_map.keys(), help="The attack algorithm to use.")

    # Add arguments from base class and the specific attack class
    BaseAttack.add_common_args(parser)
    AttackClass.add_attack_args(parser)

    # --- Manual Validation for Executable ---
    final_args = parser.parse_args()
    if not final_args.raw_args_template and not final_args.executable:
        parser.error("Either --executable or --raw-args-template must be provided.")

    # Run the attack
    attack_instance = AttackClass(final_args)
    attack_instance.run()

if __name__ == "__main__":
    main()
