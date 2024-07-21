import os
import requests
import time

def creating_file_name_list():
    file_name_list = []

    for dirpath, dirnames, filenames in os.walk(r'C:\My_Path'):  #replace with a real path in your computer that you want to check
        print(f'Found directory: {dirpath}')
        for filename in filenames:
            file_name_list.append(os.path.join(dirpath, filename))

    return file_name_list

def upload_file_to_virus_total(file_path, api_key):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': api_key
    }
    files = {
        'file': (os.path.basename(file_path), open(file_path, 'rb'))
    }

    try:
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()  
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred while uploading {file_path}: {http_err}')
        return None
    except requests.exceptions.ConnectionError as conn_err:
        print(f'Connection error occurred while uploading {file_path}: {conn_err}')
        return None
    except requests.exceptions.Timeout as timeout_err:
        print(f'Timeout error occurred while uploading {file_path}: {timeout_err}')
        return None
    except requests.exceptions.RequestException as req_err:
        print(f'An error occurred while uploading {file_path}: {req_err}')
        return None
    finally:
        files['file'][1].close()  

    if response.status_code == 200:
        print(f'File {file_path} uploaded successfully.')
        analysis_id = response.json().get('data', {}).get('id')
        return analysis_id
    else:
        print(f'Upload failed for {file_path}. Status code:', response.status_code)
        print('Response:', response.text)
        return None

def get_analysis_report(analysis_id, api_key):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {
        'x-apikey': api_key
    }

    while True:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  #
        except requests.exceptions.HTTPError as http_err:
            print(f'HTTP error occurred while retrieving report: {http_err}')
            return None
        except requests.exceptions.ConnectionError as conn_err:
            print(f'Connection error occurred while retrieving report: {conn_err}')
            return None
        except requests.exceptions.Timeout as timeout_err:
            print(f'Timeout error occurred while retrieving report: {timeout_err}')
            return None
        except requests.exceptions.RequestException as req_err:
            print(f'An error occurred while retrieving report: {req_err}')
            return None

        analysis_status = response.json().get('data', {}).get('attributes', {}).get('status')
        if analysis_status == 'completed':
            return response.json()
        else:
            print('Analysis in progress, waiting...')
            time.sleep(10)

def check_for_malware(report):
    stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    if malicious > 0:
        return True
    else:
        return False

if __name__ == "__main__":
    api_key = 'YOUR_API_KEY'  # Replace with your actual VirusTotal API key
    if not api_key or api_key == 'YOUR_API_KEY':
        print("Please set your VirusTotal API key.")
    else:
        file_list = creating_file_name_list()
        
        for file_path in file_list:
            if os.path.isfile(file_path): 
                analysis_id = upload_file_to_virus_total(file_path, api_key)
                if analysis_id:
                    report = get_analysis_report(analysis_id, api_key)
                    if report:
                        print(f'Analysis report for {file_path}:')
                        if check_for_malware(report):
                            print(f'The file {file_path} contains malware.')
                        else:
                            print(f'The file {file_path} is clean.')
                    else:
                        print(f'Failed to retrieve analysis report for {file_path}')
            else:
                print(f"File not found: {file_path}")

