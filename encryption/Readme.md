# Navigate to project directory
cd /home/kali/Ransomware-Script

# Verify files
ls
# Output: decryption  package.json  system-encrypt.js

# Run pkg to create the executable
pkg . --targets node18-win-x64 --output encrypt.exe
# Output: pkg@5.8.1 (indicating successful execution)

# Verify the executable was created
ls
# Output: decryption  encrypt.exe  package.json  system-encrypt.js
