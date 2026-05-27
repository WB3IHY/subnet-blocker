import sys
from pathlib import Path
from unittest.mock import MagicMock

# Allow tests to import project modules without installation
sys.path.insert(0, str(Path(__file__).parent.parent))

# python3-nftables is an apt package unavailable in dev/CI environments;
# stub it out so modules that import it can be loaded and tested.
sys.modules.setdefault("nftables", MagicMock())
