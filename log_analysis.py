import re
import csv
from collections import defaultdict

def read_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def get_request_count_by_ip(log_lines):
    ip_request_counts = defaultdict(int)
    for line in log_lines:
        match = re.match(r'(\S+) - - \[.*\] ".*" \d{3} \d+.*', line)
        if match:
            ip_address = match.group(1)
            ip_request_counts[ip_address] += 1
    return ip_request_counts

def get_most_accessed_endpoint(log_lines):
    endpoint_counts = {}
    for line in log_lines:
        try:
            endpoint = line.split('"')[1].split()[1]
            endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
        except IndexError:
            continue
    if not endpoint_counts:
        raise ValueError("No endpoints found in the log file.")
    return max(endpoint_counts.items(), key=lambda x: x[1])

def detect_suspicious_activity(log_lines, threshold=10):
    failed_logins = defaultdict(int)
    for line in log_lines:
        match = re.match(r'(\S+) - - \[.*\] ".*" 401 \d+ "Invalid credentials"', line)
        if match:
            ip_address = match.group(1)
            failed_logins[ip_address] += 1
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def display_results(ip_counts, most_accessed_endpoint, suspicious_activity):
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    print(f"\nMost Frequently Accessed Endpoint: {most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, output_file='log_analysis_results.csv'):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, count in ip_counts.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})
        writer.writerow({'IP Address': 'Most Frequently Accessed Endpoint', 
                         'Request Count': f'{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)'})
        writer.writerow({'IP Address': 'Suspicious Activity Detected', 'Request Count': 'Failed Login Count'})
        for ip, count in suspicious_activity.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

def main():
    log_file = 'sample.log'
    log_lines = read_log_file(log_file)
    ip_counts = get_request_count_by_ip(log_lines)
    most_accessed_endpoint = get_most_accessed_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)
    display_results(ip_counts, most_accessed_endpoint, suspicious_activity)
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()
