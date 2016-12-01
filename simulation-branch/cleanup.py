"""
Cleanup script. Removes state files used by EM and BB.

!!! DO NOT RUN IT WHILE EM AND BB SERVERS ARE RUNNING !!!
"""

import os

try:
    os.remove("em.pickle")
except FileNotFoundError:
    pass

try:
    os.remove("bb.pickle")
except FileNotFoundError:
    pass

print("DONE")
