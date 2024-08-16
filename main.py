import os
import re
import tempfile
from flask import Flask, request, render_template, jsonify
from androguard.core.bytecodes.apk import APK

app = Flask(__name__)

# Define regex patterns
url_pattern = re.compile(
    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)

ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

network_libs = re.compile(
    r'(HttpURLConnection|OkHttpClient|Retrofit|HttpClient|Request|Response|AsyncTask)',
    re.IGNORECASE)


def decompile_apk_with_jadx(apk_file, output_dir):
    """Decompile APK using JADX."""
    os.system(f'jadx -d {output_dir} {apk_file}')


def check_trustworthiness(apk_file):
    """Check APK for permissions, activities, receivers, and services."""
    apk = APK(apk_file)

    # Check permissions
    permissions = apk.get_permissions()

    # Check activities
    activities = apk.get_activities()

    # Check receivers
    receivers = apk.get_receivers()

    # Check services
    services = apk.get_services()

    return {
        'permissions': permissions,
        'activities': activities,
        'receivers': receivers,
        'services': services
    }


def extract_from_file(file_path):
    """Extract URLs, IP addresses, and network libraries from a given file."""
    urls = set()
    ips = set()
    network_classes = set()

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            urls.update(url_pattern.findall(content))
            ips.update(ip_pattern.findall(content))
            network_classes.update(network_libs.findall(content))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

    return urls, ips, network_classes


def extract_from_directory(directory_path):
    """Extract URLs, IP addresses, and network libraries from source files in a directory."""
    all_urls = set()
    all_ips = set()
    all_network_classes = set()

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.java'):  # Focus on source files
                file_path = os.path.join(root, file)
                urls, ips, network_classes = extract_from_file(file_path)
                all_urls.update(urls)
                all_ips.update(ips)
                all_network_classes.update(network_classes)

    return all_urls, all_ips, all_network_classes


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and initiate analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Use a temporary directory for the APK and decompiled files
    with tempfile.TemporaryDirectory() as temp_dir:
        apk_path = os.path.join(temp_dir, file.filename)
        file.save(apk_path)

        # Decompile APK with JADX
        decompile_directory = os.path.join(temp_dir, 'decompiled')
        decompile_apk_with_jadx(apk_path, decompile_directory)

        # Check trustworthiness
        trustworthiness = check_trustworthiness(apk_path)

        # Extract Java files and scan for IPs, URLs, network libraries
        urls, ips, network_classes = extract_from_directory(
            decompile_directory)

    return render_template('results.html',
                           trustworthiness=trustworthiness,
                           urls=urls,
                           ips=ips,
                           network_classes=network_classes)


@app.route('/')
def index():
    """Render the index page for file upload."""
    return render_template('index.html')
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
