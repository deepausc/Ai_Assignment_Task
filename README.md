<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3rd Party Software Security Management</title>
</head>
<body>

<h1>3rd Party Software Security Management</h1>

<h2>Table of Contents</h2>
<ul>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#features">Features</a></li>
    <li><a href="#technologies-used">Technologies Used</a></li>
    <li><a href="#prerequisites">Prerequisites</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#file-structure">File Structure</a></li>
    <li><a href="#api-endpoints">API Endpoints</a></li>
    <li><a href="#analyzing-sbom-for-vulnerabilities">Analyzing SBOM for Vulnerabilities</a></li>
    <li><a href="#assessing-vulnerabilities-by-cve-id">Assessing Vulnerabilities by CVE ID</a></li>
</ul>

<h2 id="overview">Overview</h2>
<p>This system is designed to demonstrate the following workflows:</p>
<ul>
    <li>SBOM Request and Delivery</li>
    <li>Vulnerability Remediation Request and Response</li>
    <li>Continuous Monitoring and Risk Assessment</li>
</ul>
<p>The system is implemented using Python and leverages open-source libraries and frameworks such as FastAPI, Hugging Face Transformers, and LangChain.</p>

<h2 id="features">Features</h2>
<ul>
    <li>Generate SBOMs for packages and Docker images.</li>
    <li>Analyze SBOM artifacts for vulnerabilities using the NVD API.</li>
    <li>Manage vendors, products, vulnerabilities, and fixes via API.</li>
    <li>Support for PostgreSQL database to store SBOM-related data.</li>
</ul>

<h2 id="technologies-used">Technologies Used</h2>
<ul>
    <li><strong>FastAPI</strong>: For building APIs for Agents.</li>
    <li><strong>SQLAlchemy</strong>: ORM for database interactions.</li>
    <li><strong>PostgreSQL</strong>: Relational database for data storage.</li>
    <li><strong>NVD API</strong>: National Vulnerability Database API for querying vulnerabilities.</li>
    <li><strong>Pydantic</strong>: For data validation and parsing in FastAPI.</li>
    <li><strong>Syft</strong>: For SBOM generation and analysis.</li>
    <li><strong>Docker</strong>: For containerization.</li>
    <li><strong>PGAdmin</strong>: For database management.</li>
    <li><strong>pgvector</strong>: For database vector embeddings of vulnerabilities knowledgebase.</li>
</ul>

<h2 id="prerequisites">Prerequisites</h2>
<ol>
    <li><strong>Python 3.8+</strong></li>
    <li><strong>PostgreSQL</strong> installed and running in Docker container.</li>
    <li><strong>Docker</strong> For creating container for every Agent.</li>
    <li><strong>Syft</strong>: Installed for SBOM generation.</li>
    <li><strong>pip</strong> for package Installations.</li>
</ol>

<h2 id="installation">Installation</h2>
<ol>
    <li><strong>Clone the repository:</strong>
        <pre><code>git clone https://github.com/yourusername/your-repo.git
cd your-repo</code></pre>
    </li>
    <li><strong>Setup pgadmin:</strong>
        <pre><code>docker pull dpage/pgadmin4
docker run --name pgadmin-container -p 5050:80 -e PGADMIN_DEFAULT_EMAIL=user@domain.com -e PGADMIN_DEFAULT_PASSWORD=password -d dpage/pgadmin4</code></pre>
    </li>
    <li><strong>Setup pgvector:</strong>
        <pre><code>docker pull pgvector/pgvector:pg16
docker volume create pgvector-data
docker run --name pgvector-container -e POSTGRES_PASSWORD=password -p 5432:5432 -v pgvector-data:/var/lib/postgresql/data -d pgvector/pgvector:pg16</code></pre>
    </li>
</ol>

<h2 id="file-structure">File Structure</h2>
<pre>
Here's a detailed file structure of the project:
├── BuyerAgent/
│   ├── BuyerAgent.py
├── create_pgsqltables.py
│   ├── Dockerfile
│   └── requirements.txt
├── fixAgent/
│   ├── fixagent.py
│   ├── dockerfile
│   └── pycache/
├── integrationAgent/
│   ├── fapi_integrationAgent.py
│   ├── dockerfile
│   ├── requirements.txt
│   ├── readme.md
│   ├── .dockerignore
│   └── pycache/
├── SecurityAgent/
│   ├── securityAgent.py
│   ├── dockerfile
│   ├── requirements.txt
│   ├── .dockerignore
│   └── pycache/
└── VendorAgent/
    ├── VendorAgent.py
    ├── dockerfile
    ├── docker-compose.yaml
    ├── requirements.txt
    ├── kotlin-stdlib-1.4.21.jar
    ├── log4j-core-3.0.0-beta2.jar
    ├── log4j-nosql-2.3.2-javadoc.jar
    ├── log4j-web-2.3.2-javadoc.jar
    ├── openssl-1_1_1.jar
    └── poi-5.3.0.jar
    └── README.md
</pre>

<h2 id="api-endpoints">API Endpoints</h2>

<h3>BuyerAgent</h3>
<ul>
    <li><strong>Request SBOM: BuyerAgent</strong>
        <ul>
            <li>Buyers send a request with a product_id to the <code>/request_sbom/</code> endpoint.</li>
            <li>The API forwards this request to the Integration Agent.</li>
            <li>The Integration Agent retrieves the SBOM from the Vendor API.</li>
            <li>The SBOM is then sent back to the buyer.</li>
        </ul>
    </li>
    <li><strong>Assess SBOM Risk:</strong>
        <ul>
            <li>Buyers send SBOM data to the <code>/assess_sbom_risk/</code> endpoint.</li>
            <li>The API forwards the SBOM data to the Integration Agent.</li>
            <li>The Integration Agent uses the Security Agent API to evaluate the risk.</li>
            <li>The risk assessment results are returned to the buyer.</li>
        </ul>
    </li>
</ul>

<h3>IntegrationAgent</h3>
<ul>
    <li><strong>Check API Status:</strong>
        <ul>
            <li><strong>Endpoint:</strong> <code>/</code></li>
            <li><strong>Function:</strong> Returns a simple message greet to confirm the API is working.</li>
        </ul>
    </li>
    <li><strong>Get SBOM:</strong>
        <ul>
            <li><strong>Endpoint:</strong> <code>/get_sbom</code></li>
            <li><strong>Function:</strong> Receives a request with a product_id and forwards it to the Vendor API to retrieve the SBOM. Returns the response from the Vendor API.</li>
        </ul>
    </li>
    <li><strong>Access SBOM:</strong>
        <ul>
            <li><strong>Endpoint:</strong> <code>/acess_sbom</code></li>
            <li><strong>Function:</strong> Receives SBOM JSON data from the buyer and forwards it to the Security API for vulnerability analysis. Returns the analysis results from the Security API.</li>
        </ul>
    </li>
</ul>

<h3>VendorAgent</h3>
<p>Here's a breakdown of how the FastAPI application works:</p>
<ul>
    <li><strong>Generate SBOM:</strong>
        <ul>
            <li><strong>Endpoint:</strong> <code>/generate-sbom/</code></li>
            <li><strong>Function:</strong> Generates a Software Bill of Materials (SBOM) for a specific JAR file based on the product_id provided.</li>
            <li><strong>Process:</strong>
                <ul>
                    <li>Receives a product_id in the request.</li>
                    <li>Maps product_id to a specific JAR file path.</li>
                    <li>Checks if the file exists at the specified location.</li>
                    <li>Calls the <code>generate_sbom()</code> function to generate the SBOM using the syft tool.</li>
                    <li>Returns the generated SBOM as a JSON response.</li>
                </ul>
            </li>
        </ul>
    </li>
</ul>

<h3>SecurityAgent</h3>
<ul>
    <li><strong>Analyze SBOM:</strong>
        <ul>
            <li><strong>Endpoint:</strong> <code>/analyze-sbom</code></li>
            <li><strong>Function:</strong> Analyze the provided SBOM JSON to identify vulnerabilities.</li>
        </ul>
    </li>
    <li><strong>Assess Vulnerability:</strong>
        <ul>
            <li><strong>Endpoint:</strong> <code>/assess-vulnerability</code></li>
            <li><strong>Function:</strong> Assess vulnerabilities based on CVE IDs.</li>
        </ul>
    </li>
</ul>

<h2 id="analyzing-sbom-for-vulnerabilities">Analyzing SBOM for Vulnerabilities</h2>
<ol>
    <li>The SBOM data is provided by the user.</li>
    <li>The data is sent to the <code>/analyze-sbom</code> endpoint of the Security API.</li>
    <li>The Security API uses NVD data to identify potential vulnerabilities in the SBOM.</li>
</ol>

<h2 id="assessing-vulnerabilities-by-cve-id">Assessing Vulnerabilities by CVE ID</h2>
<ol>
    <li>The CVE ID is provided by the user.</li>
    <li>The CVE ID is sent to the <code>/assess-vulnerability</code> endpoint of the Security API.</li>
    <li>The Security API queries the NVD to retrieve information about the CVE.</li>
    <li>Returns vulnerability assessment information to the user.</li>
</ol>

</body>
</html>
# Ai_Assignment_Task
