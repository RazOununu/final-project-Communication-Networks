# final-project-Communication-Networks

This project analyzes network traffic captured in PCAP files by extracting key characteristics from each packet and exporting the data to CSV files. These CSV files are then used to generate a series of graphs that help compare and visualize the behavior of different applications.

## Project Overview

The project processes PCAP files along with optional TLS keys files (in .log format) and creates a corresponding CSV file for each capture. The CSV files include the following key characteristics:

- **Timestamp:** The time at which the packet was captured.
- **Packet Length:** The size of the packet in bytes.
- **Source IP & Destination IP:** The IP addresses of the sender and receiver.
- **IP Version:** Indicates whether the packet is IPv4 or IPv6.
- **TTL (Time To Live):** The remaining number of hops a packet can take before being discarded. Although we only see the final TTL value, when compared with known default values (e.g., 64, 128, or 255), it can help infer the number of network hops.
- **Protocol:** The protocol identified in the packet. In our analysis, this is filtered to only include TCP, TLS, and UDP. Any packet not matching these will be labeled as "Other."
- **Source Port & Destination Port:** The port numbers used by the packet.
- **TCP Flags:** Control flags (e.g., SYN, ACK, FIN) that indicate the state of a TCP connection.
- **TCP Window Size:** The window size that indicates the amount of data the sender is willing to receive.
- **TLS Fields (Version, Content Type, Record Length):** When available, these fields provide information about the encryption and handshake process for secure traffic.
- **Flow Hash:** A computed hash based on IP addresses, ports, and protocol used to group packets belonging to the same communication flow.
- **Packet Inter-arrival Time:** The time difference between consecutive packets, which can help analyze timing and traffic patterns.

## Why These Characteristics?

- **Timestamp & Inter-arrival Time:** Provide insights into the timing, pacing, and possible congestion within the network.
- **Packet Length:** Helps distinguish between different types of traffic (e.g., video streaming often uses larger packets than text-based communications).
- **IP Addresses & IP Version:** Reveal details about network topology, the use of CDNs, and whether the traffic is local (LAN) or external (WAN).
- **TTL:** Although we only see the final value, when compared to typical default values (64, 128, or 255), TTL can give an indication of the number of hops and network distance.
- **Protocol, Ports, TCP Flags, and Window Size:** Allow us to understand the nature of the communication at the transport layer and to infer behaviors like connection establishment and flow control.
- **TLS Fields:** Provide insight into the encryption process and secure communication.
- **Flow Hash:** Enables the grouping of packets into flows, facilitating analysis of overall flow behavior such as size and volume.
  
## How It Works

1. **Extraction Process:**  
   The script uses [PyShark](https://github.com/KimiNewt/pyshark) to process each PCAP file. If a corresponding TLS key file is available, it is used to decrypt TLS traffic. The script iterates through each packet, extracts the above characteristics, and stores them as a dictionary. All dictionaries are then written as rows into a CSV file.

2. **CSV Creation:**  
   Each PCAP file results in one CSV file stored in the `output` folder. These CSV files serve as the basis for generating various graphs.

3. **Graph Generation:**  
The project includes several plotting functions that visualize various network traffic characteristics using Matplotlib (and sometimes Seaborn):

- **Protocol Distribution:** A grouped bar chart comparing the number of TCP, TLS, and UDP packets across applications.
- **TTL Distribution:** A grouped bar chart showing packet counts in different TTL bins, which can hint at the number of network hops.
- **Packet Length Distribution:** Both histogram and density (KDE) plots illustrate how packet sizes are distributed across applications.
- **Packet Size Distribution:** A grouped bar chart displaying how packets are distributed into predefined size bins, allowing for comparison of packet sizes between applications.
- **Average Packet Inter-arrival Time:** A bar chart showing the average time between consecutive packets for each application.
- **TCP Flags Distribution:** A grouped bar chart showing the frequency of various TCP flags.
- **TCP Window Size Over Time:** A smoothed line plot depicting the evolution of TCP window size throughout the capture.
- **TLS Grouped Chart:** A grouped bar chart comparing TLS header fields (Version, Content Type, and Record Length) across applications.
- **Flow Size and Flow Volume:** Line plots that display the number of packets per flow and the total volume (in bytes) transmitted.

These visualizations provide a comprehensive way to compare and analyze the behavior of different applications based on their network traffic characteristics.
## Requirements - Directory Structure and Setup Instructions

- Python 3.x
- [PyShark](https://github.com/KimiNewt/pyshark)
- Matplotlib
- Pandas
- Seaborn (for some plots)
- NumPy

You can install the necessary packages using:

```bash
pip install pyshark matplotlib pandas seaborn numpy
```

## Project Structure

```
CommunicationNetworksProject/
├── captures/          # Folder containing PCAP files (.pcapng)
├── logs/              # Folder containing TLS key files (.log)
├── output/            # CSV files and graphs will be saved here
├── main.py            # Main script (contains code for processing and plotting)
└── README.md          # This file
```

## How to Run

1. **File Naming & Placement:**  
   - Place your PCAP files in the `captures` folder. **Note:** The PCAP files must have the extension `.pcapng` (not `.pcap`).
   - Place your TLS key files (if any) in the `logs` folder.  
   **Important:** Each TLS key file must have the exact same base name as its corresponding PCAP file. For example, if there is a PCAP file named `youtube.pcapng` in the `captures` folder, its corresponding TLS key file must be named `youtube.log` and placed in the `logs` folder.  
   If these naming conventions or directory placements are not followed, the code will not be able to correctly read and process the PCAP files.


2. Run the main script from the project root:

   ```bash
   python main.py
   ```

This will process all PCAP files, generate CSV files in the `output` folder, and produce various graphs for analysis.

## Conclusion

This project provides a systematic way to analyze network traffic by extracting and visualizing key characteristics from PCAP files. The generated CSV files offer a structured format for detailed analysis, and the accompanying graphs enable quick comparison and insight into the behavior of different applications.
Below is an updated "Acknowledgements" section that you can add to your README file. You can copy and integrate it directly into your project README:

---

## Acknowledgements

This project was developed with the assistance of several beginner-friendly resources. In particular, we consulted:

- The YouTube video [“Intro to PyShark”](https://www.youtube.com/watch?v=8G0XIQPJszs) to understand the basics of PyShark.
- The article [“Intro to PyShark” on The Packet Geek](https://thepacketgeek.com/pyshark/intro-to-pyshark/) for additional insights on using PyShark.
- The tutorial available at [GeeksforGeeks: Python Seaborn Tutorial](https://www.geeksforgeeks.org/python-seaborn-tutorial/) helped us discover additional visualization tools for our graphs.
- We also benefited from the assistance provided by ChatGPT .

These resources were invaluable in helping us understand how to capture, process, and analyze network traffic using PyShark, as well as in designing and implementing the various visualization components.

---
Below is an example "Authors" section that you can add to your README file. You can customize the names and ID numbers as needed:

---

## Authors

This project was developed by the following contributors:

- **רעות בכור** (ID: 012345678)
- **רז אונונו** (ID: 987654321)
- **שירת הוטרר** (ID: 123456789)
- **נועה הוניגשטיין** (ID: 329808554)


---

This README was written partly with the help of Google Translate and ChatGPT to ensure clarity and proper structure.

