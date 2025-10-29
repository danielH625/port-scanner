#!/bin/python3

import socket
import sys


def help_flag():
  print(
      "Usage: python3 port_scanner.py [Scan Type] [Ip Address] [Port Specification] [Port Options]"
  )
  print(" Scan Types:")
  print("  -sT\t\tShow help options")
  print("  -sU\t\tRead the hashes from a file")
  print(" Port Specification:")
  print("  -p\t\tScan specified ports")
  print("  -p-\t\tScan all 65536 ports")


def check_tcp_port(host, port, timeout=1.0):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(timeout)

  try:
    s.connect((host, port))

  except:
    return False

  else:
    return True

  finally:
    s.close()


def scan_invividual_ports(host, ports):
  for port in ports:
    if check_tcp_port(host, port):
      print(f"[+] {host}:{port} is open")

    else:
      print(f"[+] {host}:{port} is closed")


def scan_range_ports(host, start_port, end_port):
  for port in range(start_port, end_port):
    if check_tcp_port(host, port):
      print(f"[+] {host}:{port} is open")

    else:
      continue


def check_port_spec_list(port_spec):
  if port_spec == "-p":
    temp_ports = sys.argv[4]
    ports = []

    if "," in temp_ports:
      temp_ports = temp_ports.split(",")
      for port in temp_ports:
        ports.append(int(port))

    elif temp_ports.isdigit():
      ports.append(int(temp_ports))

    else:
      print("Error: Incorrect use of ports, view the help options:")
      help_flag()

    return ports


def check_port_spec_range(port_spec):
  start_port = 0
  end_port = 0

  if port_spec == "-p":
    ports = sys.argv[4]

    if "-" in ports:
      ports = ports.split("-")
      start_port += int(ports[0])
      end_port += int(ports[1])

  elif port_spec == "-p-":
    start_port += 1
    end_port += 65537

  else:
    print("Error: Incorrect use of ports, view the help options:")
    help_flag()

  return start_port, end_port


try:
  scan_type = sys.argv[1]

  if scan_type == "-h":
    help_flag()

  if scan_type == "-sT":
    host = sys.argv[2]
    port_spec = sys.argv[3]

    if port_spec == "-p-" or "-" in sys.argv[4]:
      start_port, end_port = check_port_spec_range(port_spec)
      scan_range_ports(host, start_port, end_port)

    elif "," in sys.argv[4] or sys.argv[4].isdigit():
      ports = check_port_spec_list(port_spec)
      scan_invividual_ports(host, ports)

except:
  help_flag()

else:
  print("Port scan complete")
