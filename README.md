Hop-by-Hop (Burp Suite Extension)
==========================================

**A Tool for Exploiting Hop-by-Hop Header Stripping Vulnerabilities**

Overview
--------

**Hop-by-Hop Assassin** is a Burp Suite extension designed to detect and exploit a specific misconfiguration in reverse proxies and load balancers compliant with RFC 2616.

The HTTP specification defines the `Connection` header as a control mechanism to specify which headers are "Hop-by-Hop" (meaning they should be processed by the proxy and removed before forwarding to the backend). Attackers can abuse this by adding sensitive headers (like `X-Forwarded-For` or `Cookie`) to the `Connection` header. If the proxy obeys, it strips the security headers, potentially bypassing Access Control Lists (ACLs) or authentication checks on the backend.

This extension automates the discovery of this vulnerability by fuzzing the `Connection` header and performing differential analysis on the responses.

Features
--------

-   **Smart Discovery:** Automatically identifies all headers present in the request and tests them for removal.

-   **Common Target List:** Includes a built-in dictionary of high-value targets often used for IP restriction (e.g., `X-Forwarded-For`, `Real-IP`, `True-Client-IP`).

-   **Differential Analysis:** Compares the status code and content length of the probed response against a baseline request. Only significant anomalies are logged to minimize noise.

-   **Dedicated UI:** Results are displayed in a "Hop Assassin" tab with a split-view request/response editor.

Installation
------------

### Prerequisites

-   Java Development Kit (JDK) 21.

-   Burp Suite (Community or Professional).

-   Gradle.

### Build from Source

1.  Clone the repository:

    ```
    git clone https://github.com/tobiasGuta/Hop-by-Hop-Burp-Suite-Extension.git
    cd Hop-by-Hop-Burp-Suite-Extension

    ```

2.  Build the JAR file:

    ```
    ./gradlew clean jar

    ```

3.  Load into Burp Suite:

    -   Navigate to **Extensions** -> **Installed**.

    -   Click **Add** -> Select `build/libs/HopAssassin.jar`.

Usage Guide
-----------

1.  **Identify a Target:** Find a request that returns a `403 Forbidden` or `401 Unauthorized` due to a header restriction (e.g., IP blocking).

2.  **Launch Probe:**

    -   Right-click the blocked request in Proxy or Repeater.

    -   Select **Probe Hop-by-Hop Headers**.

3.  **Analyze Results:**

    -   Open the **"Hop Assassin"** tab.

    -   Look for rows where the Status Code changed (e.g., 403 -> 200) or the Response Length changed significantly.

    -   Click the row to verify that the specific header was removed.

Tech Stack
----------

-   **Language:** Java 21

-   **API:** Burp Suite Montoya API

-   **UI Components:** Swing (JTable, JSplitPane, Burp Native Editors)

https://github.com/user-attachments/assets/21ed50d3-5ac3-42b7-a4f6-aaf5702a1e42

Disclaimer
----------

This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.
