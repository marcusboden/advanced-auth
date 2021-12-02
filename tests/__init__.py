import sys
from unittest import mock

# mock shutil for all tests
shutil = mock.MagicMock()
shutil.chown = mock.MagicMock()
sys.modules['shutil'] = shutil
