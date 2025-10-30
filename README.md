setup:
# Clone or download the script
git clone <repository-url>
cd sql-injection-fuzzer

# Install dependencies
pip install requests

# Make executable (optional)
chmod +x sql_injection_fuzzer.py


For more help:
python3 injection.py --help

usage:
python3 injection.py "http://target.com/login.php" -p username -i 400 -t 5

