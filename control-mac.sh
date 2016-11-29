# As of now, sadly, must enter path to files by hand.
# If em.py takes more than 5 seconds to set up, may crash
#  Adjust as needed

osascript -e 'tell app "Terminal"
    do script "cd Desktop/Paillier-E-Voting-ishaq; python3 em.py"' -e 'delay 5' -e 'do script "cd Desktop/Paillier-E-Voting-ishaq; python3 bb.py"' -e 'do script "cd Desktop/Paillier-E-Voting-ishaq; python3 voter.py"' -e 'end tell'

read -n 1 -p "Enter Key when finished with voting to clean. "

python3 cleanup.py
    
