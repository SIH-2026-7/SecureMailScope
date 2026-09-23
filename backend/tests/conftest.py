import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'dataset_generation'))
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='securemailscope-tests-')
