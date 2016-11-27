"""
Cleanup script. Removes state files used by EM and BB.

!!! DO NOT RUN IT WHILE EM AND BB SERVERS ARE RUNNING !!!
"""

import os

os.remove("em.pickle")
os.remove("bb.pickle")
