\# Codex instructions

This project uses the Windows conda environment `testtorch`.

Never run bare `python`, `pip`, or `pytest`.

Always run Python commands through conda:

conda run -n testtorch python
conda run -n testtorch python -m pip
conda run -n testtorch python -m pytest

Before saying torch is missing, verify with:

conda run -n testtorch python -c "import sys, torch; print(sys.executable); print(torch.__version__)"



