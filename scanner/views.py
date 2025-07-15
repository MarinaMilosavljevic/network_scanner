import ipaddress
import json
import re
import socket
import subprocess
import concurrent.futures

from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.utils import timezone

from .forms import ScanForm, UserRegisterForm
from .models import ScanResult


def register_view(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('scan_form')
    else:
        form = UserRegisterForm()
    return render(request, 'register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('scan_form')
        else:
            return render(request, 'scanner/login.html', {'error': 'Invalid credentials'})
    return render(request, 'scanner/login.html')


def logout_view(request):
    logout(request)
    return redirect('/login')


def parse_nmap_output(nmap_output):
    ports = []
    lines = nmap_output.splitlines()
    parsing = False
    for line in lines:
        if re.match(r'^PORT\s+STATE\s+SERVICE', line):
            parsing = True
            continue
        if parsing:
            if line.strip() == '':
                break
            parts = re.split(r'\s+', line, maxsplit=4)
            if len(parts) >= 3:
                port_info = {
                    'port': parts[0],
                    'state': parts[1],
                    'service': parts[2],
                    'version': parts[3] if len(parts) > 3 else '',
                    'protocol': parts[0].split('/')[1] if '/' in parts[0] else ''
                }
                ports.append(port_info)
    return ports


def ping_host(ip, param):
    try:
        result = subprocess.run(['ping', param, '1', str(ip)],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=2)
        if result.returncode == 0:
            return str(ip)
    except subprocess.TimeoutExpired:
        return None
    return None


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def run_ping_sweep_with_hostname(network):
    alive_hosts = []
    param = '-n' if subprocess.os.name == 'nt' else '-c'

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_host, ip, param): ip for ip in network.hosts()}
        for future in concurrent.futures.as_completed(futures):
            ip = future.result()
            if ip:
                hostname = get_hostname(ip)
                if hostname:
                    alive_hosts.append(f"{ip} ({hostname})")
                else:
                    alive_hosts.append(ip)

    return "Alive hosts:\n" + "\n".join(alive_hosts) if alive_hosts else "No hosts alive in the given network."


def run_nmap_ping_sweep(network):
    try:
        result = subprocess.run(['nmap', '-sn', str(network)], capture_output=True, text=True, timeout=60)
        alive_hosts = []
        for line in result.stdout.splitlines():
            if line.startswith('Nmap scan report for'):
                parts = line.split('for ')[1]
                if '(' in parts and ')' in parts:
                    ip = parts.split('(')[0].strip()
                    host = parts.split('(')[1].replace(')', '').strip()
                    alive_hosts.append(f"{ip} ({host})")
                else:
                    alive_hosts.append(parts.strip())
        return "Alive hosts:\n" + "\n".join(alive_hosts) if alive_hosts else "No hosts alive."
    except Exception as e:
        return f"Error during nmap ping sweep: {e}"


def run_scan(target, scan_type):
    try:
        if scan_type == 'nmap':
            result = subprocess.run(['nmap', target], capture_output=True, text=True, timeout=60)
            return result.stdout if result.returncode == 0 else f"Scan failed: {result.stderr}"

        elif scan_type == 'ping':
            param = '-n' if subprocess.os.name == 'nt' else '-c'
            result = subprocess.run(['ping', param, '4', target], capture_output=True, text=True, timeout=30)
            return result.stdout if result.returncode == 0 else f"Ping failed: {result.stderr}"

        elif scan_type == 'ping_sweep':
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError:
                return "Invalid network address format for ping sweep."

            return run_ping_sweep_with_hostname(network)

        elif scan_type == 'nmap_ping_sweep':
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError:
                return "Invalid network address format for ping sweep."

            return run_nmap_ping_sweep(network)

        else:
            return "Unsupported scan type."

    except FileNotFoundError:
        return "Required tool not found. Please install nmap or ensure ping is available."
    except subprocess.TimeoutExpired:
        return "Scan timed out."


@login_required
def scan_form_view(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            target = form.cleaned_data['target']
            scan_type = form.cleaned_data['scan_type']
            result_text = run_scan(target, scan_type)

            scan = ScanResult.objects.create(
                target=target,
                scan_type=scan_type,
                scanned_at=timezone.now(),
                result=result_text,
                user=request.user
            )
            return redirect('scan_result', scan_id=scan.id)
    else:
        form = ScanForm()

    return render(request, 'scanner/scan_form.html', {'form': form})


@login_required
def scan_result_view(request, scan_id):
    scan = get_object_or_404(ScanResult, id=scan_id)

    if scan.user != request.user:
        return redirect('scan_form')

    ports = None
    if scan.scan_type == 'nmap':
        ports = parse_nmap_output(scan.result)

    return render(request, 'scanner/scan_result.html', {'scan': scan, 'ports': ports})


@login_required
def scan_history_view(request):
    query = request.GET.get('q', '')
    scans = ScanResult.objects.filter(user=request.user).order_by('-scanned_at')
    if query:
        scans = scans.filter(target__icontains=query)
    return render(request, 'scanner/scan_history.html', {'scans': scans, 'query': query})
