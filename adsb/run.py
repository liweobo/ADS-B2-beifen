"""Compatibility entry point for ``conda run -n testtorch python -m adsb.run``."""

from adsb.checkpoints import load_detector_checkpoint, save_detector_checkpoint
from adsb.cli import main_entry, parse_args
from adsb.experiment import main
from adsb.inference import run_checkpoint_on_new_csv

__all__ = [
    "load_detector_checkpoint",
    "main",
    "main_entry",
    "parse_args",
    "run_checkpoint_on_new_csv",
    "save_detector_checkpoint",
]

if __name__ == "__main__":
    main_entry()
