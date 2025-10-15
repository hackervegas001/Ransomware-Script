# Navigate to project directory
cd /home/kali/Ransomware-Script

# Verify files
ls
# Output: encryption  package.json  system-decrypt.js

# Run pkg to create the executable
pkg . --targets node18-win-x64 --output decrypt.exe
# Output: pkg@5.8.1 (indicating successful execution)

# Verify the executable was created
ls
# Output: encryption  decrypt.exe  package.json  system-decrypt.js
