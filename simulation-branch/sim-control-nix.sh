
# Run in a loop so many voters! Let's say 100
string=$'Voter00'
string=$string$'\nVoter00'
string=$string$'\n0\ny'
for (( i=1; i<=49; i++ )); do
    if [ $i -le 9 ] ; then
        string=$string$'\nVoter0'$i
        string=$string$'\nVoter0'$i
    else
        string=$string$'\nVoter'$i
        string=$string$'\nVoter'$i
    fi
    r=$RANDOM
    r=$((r%5))
    string=$string$'\n'$r$'\ny'
   
done
echo "$string" > sim.txt

gnome-terminal -e "bash -c \"python3 em.py; exec bash\""

read -n 1 -p "Enter Key when em.py finishes. " 

gnome-terminal -e "bash -c \"python3 bb.py; exec bash\""
gnome-terminal -e "bash -c \"python3 sim.py; exec bash\""


read -n 1 -p "Enter Key when finished with voting to clean. "
gnome-terminal -e "bash -c \"python3 cleanup.py\""


