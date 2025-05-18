import os
import json
import sys

# Get the base path for resources (works in PyInstaller and normal execution)
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller."""
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Configuration settings for the port scanner
DEFAULT_TIMEOUT = 0.5  # Default timeout in seconds
MAX_CONCURRENT = 100  # Maximum concurrent tasks
BANNER_BUFFER_SIZE = 1024  # Buffer size for banner grabbing
DEFAULT_WINDOW_SIZE = "700x700"  # Default GUI window size
TEXTBOX_WIDTH = 600  # Width for result and analysis textboxes

# NVD API settings
SETTINGS_FILE = resource_path("settings.json")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_TIMEOUT = 3600  # Cache timeout in seconds (1 hour)

# Load NVD API key from settings.json
def load_nvd_api_key():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
                return settings.get("nvd_api_key", "")
        return ""
    except Exception:
        return ""

NVD_API_KEY = load_nvd_api_key()

# Save NVD API key to settings.json
def save_nvd_api_key(api_key):
    settings = {"nvd_api_key": api_key}
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f)
    except Exception as e:
        print(f"Error saving settings: {e}")

# Predefined port settings
PREDEFINED_PORTS = {
    "Common Ports": [(1, 1024)],  # Common ports range
    "Web Servers": [(80, 80), (443, 443), (8080, 8080)],  # HTTP, HTTPS, etc.
    "FTP": [(21, 21), (22, 22)],  # FTP, SFTP/SSH
    "Custom": None  # User-defined range
}

# Language settings
LANGUAGES = {
    "en": {
        "title": "Port Scanner GUI",
        "target_label": "Target (IP, Domain, or CIDR):",
        "protocol_label": "Protocol:",
        "scan_type_label": "Scan Type:",
        "start_port_label": "Start Port:",
        "end_port_label": "End Port:",
        "timeout_label": "Timeout (seconds):",
        "predefined_ports_label": "Predefined Ports:",
        "nvd_api_key_label": "NVD API Key:",
        "start_scan": "Start Scan",
        "save_report": "Save Report",
        "new_scan": "New Scan",
        "cancel_scan": "Cancel Scan",
        "deselect_protocol": "Deselect Protocol",
        "switch_language": "Switch to Arabic",
        "scanning": "Scanning {target} from port {start} to {end} ({protocol}, {scan_type})...",
        "scan_complete": "Scan completed successfully.",
        "no_results": "No scan results to save.",
        "saved": "Results saved to {file_path}",
        "error": "Error: {error}",
        "invalid_input": "Invalid input: {error}",
        "root_privileges": "SYN Scan requires root/admin privileges. Run the program with sudo if necessary.",
        "security_analysis": "Security Analysis",
        "total_hosts": "Total Hosts Scanned: {count}",
        "open_ports": "Open Ports Found: {count}",
        "high_risk_ports": "High-Risk Ports:",
        "vulnerabilities": "Vulnerabilities:",
        "recommendations": "Recommendations:",
        "cancel_not_implemented": "Scan cancelled.",
        "save_api_key": "Save API Key",
        "api_key_saved": "NVD API Key saved successfully."
    },
    "ar": {
        "title": "واجهة ماسح المنافذ",
        "target_label": "الهدف (IP، نطاق، أو CIDR):",
        "protocol_label": "البروتوكول:",
        "scan_type_label": "نوع الفحص:",
        "start_port_label": "منفذ البداية:",
        "end_port_label": "منفذ النهاية:",
        "timeout_label": "زمن الانتظار (ثوانٍ):",
        "predefined_ports_label": "المنافذ المعدة مسبقًا:",
        "nvd_api_key_label": "مفتاح NVD API:",
        "start_scan": "بدء الفحص",
        "save_report": "حفظ التقرير",
        "new_scan": "فحص جديد",
        "cancel_scan": "إلغاء الفحص",
        "deselect_protocol": "إلغاء اختيار البروتوكول",
        "switch_language": "التحويل إلى الإنجليزية",
        "scanning": "جارٍ فحص {target} من المنفذ {start} إلى {end} ({protocol}, {scan_type})...",
        "scan_complete": "تم الفحص بنجاح.",
        "no_results": "لا توجد نتائج فحص لحفظها.",
        "saved": "تم حفظ النتائج في {file_path}",
        "error": "خطأ: {error}",
        "invalid_input": "إدخال غير صالح: {error}",
        "root_privileges": "فحص SYN يتطلب صلاحيات المدير. قم بتشغيل البرنامج باستخدام sudo إذا لزم الأمر.",
        "security_analysis": "التحليل الأمني",
        "total_hosts": "إجمالي المضيفات المفحوصة: {count}",
        "open_ports": "المنافذ المفتوحة المكتشفة: {count}",
        "high_risk_ports": "المنافذ عالية المخاطر:",
        "vulnerabilities": "الثغرات الأمنية:",
        "recommendations": "التوصيات:",
        "cancel_not_implemented": "تم إلغاء الفحص.",
        "save_api_key": "حفظ مفتاح API",
        "api_key_saved": "تم حفظ مفتاح NVD API بنجاح."
    }
}