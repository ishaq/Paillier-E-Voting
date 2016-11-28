gnome-terminal -e "bash -c \"python3 em.py; exec bash\""

read -n 1 -p "Enter Key when em.py finishes. " 

gnome-terminal -e "bash -c \"python3 bb.py; exec bash\""
gnome-terminal -e "bash -c \"python3 voter.py; exec bash\""


read -n 1 -p "Enter Key when finished with voting to clean. "
gnome-terminal -e "bash -c \"python3 cleanup.py\""


