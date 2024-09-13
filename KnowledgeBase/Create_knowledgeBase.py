import json
from transformers import AutoTokenizer, AutoModel
import torch
import psycopg2
import numpy as np
from sqlalchemy import create_engine, Column, Integer, String, Text, Date, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from pgvector.sqlalchemy import Vector
from urllib.parse import urlparse

# Define database connection details
DATABASE_URL = "postgresql://postgres:password@localhost:5432/aisbom"

# Parse the database URL
result = urlparse(DATABASE_URL)
db_name = result.path[1:]
db_user = result.username
db_password = result.password
db_host = result.hostname
db_port = result.port

# Step 1: Define SQLAlchemy models and create tables

# Create the engine
engine = create_engine(DATABASE_URL)

# Create a base class for declarative models
Base = declarative_base()

# Define the Vendors table
class Vendor(Base):
    __tablename__ = 'vendors'
    vendor_id = Column(Integer, primary_key=True, autoincrement=True)
    vendor_name = Column(String(100), nullable=False)
    contact_info = Column(String(255))

    # Relationship to Products
    products = relationship('Product', back_populates='vendor')

# Define the Products table
class Product(Base):
    __tablename__ = 'products'
    product_id = Column(Integer, primary_key=True, autoincrement=True)
    product_name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=False)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'))
    release_date = Column(Date)

    # Relationship to Vendor
    vendor = relationship('Vendor', back_populates='products')
    # Relationship to Vulnerabilities and Fixes
    vulnerabilities = relationship('Vulnerability', back_populates='product')
    fixes = relationship('Fix', back_populates='product')

# Define the Vulnerabilities table
class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    vulnerability_id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    severity = Column(String(20))
    affected_product_id = Column(Integer, ForeignKey('products.product_id'))

    # Relationship to Product and Fixes
    product = relationship('Product', back_populates='vulnerabilities')
    fixes = relationship('Fix', back_populates='vulnerability')

# Define the Fixes table
class Fix(Base):
    __tablename__ = 'fixes'
    fix_id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.vulnerability_id'))
    fixed_product_id = Column(Integer, ForeignKey('products.product_id'))
    fix_description = Column(Text)

    # Relationships to Vulnerability and Product
    vulnerability = relationship('Vulnerability', back_populates='fixes')
    product = relationship('Product', back_populates='fixes')

# Define the Advisories table
class Advisory(Base):
    __tablename__ = 'advisories'
    id = Column(String(50), primary_key=True)  # Primary key with text ID
    advisory_text = Column(Text)
    embedding = Column(Vector(300))  # Assuming a vector of dimension 300
    description = Column(Text)
    published_date = Column(Text)
    assigner = Column(String(100))

# Create the tables in the database
try:
    Base.metadata.create_all(engine)
    print("Tables created successfully!")
except Exception as e:
    print(f"An error occurred while creating tables: {e}")

# Step 2: Functions for reading JSON, generating embeddings, and storing in the database

# Read Vulnerabilities from Local JSON File
def read_vulnerabilities_from_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    advisories = []
    for item in data.get('CVE_Items', []):
        cve_data = item.get('cve', {})
        advisory = {
            "id": cve_data.get('CVE_data_meta', {}).get('ID'),
            "description": cve_data.get('description', {}).get('description_data', [{}])[0].get('value', ''),
            "assigner": cve_data.get('CVE_data_meta', {}).get('ASSIGNER'),
            "published_date": item.get('publishedDate')
        }
        advisories.append(advisory)
    return advisories

# Create Embeddings for the Description
def embed_text(text):
    tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
    model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')

    inputs = tokenizer(text, return_tensors='pt', padding=True, truncation=True)
    with torch.no_grad():
        outputs = model(**inputs)
    embeddings = outputs.last_hidden_state.mean(dim=1)
    return embeddings.numpy().flatten()

# Store Advisory and Embedding in PostgreSQL Vector Database
def store_advisory_in_db(advisory, embedding):
    try:
        print("Storing advisory in database...")
        # Establish a connection to the PostgreSQL database using extracted credentials
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port
        )
        cursor = conn.cursor()

        # Convert the numpy array to a list of floats
        embedding_list = embedding.astype(float).tolist()
        
        # Insert the advisory and embedding into the table
        cursor.execute(
            """
            INSERT INTO advisories (id, advisory_text, description, embedding, assigner, published_date) 
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE 
            SET advisory_text = EXCLUDED.advisory_text,
                description = EXCLUDED.description,
                embedding = EXCLUDED.embedding,
                assigner = EXCLUDED.assigner,
                published_date = EXCLUDED.published_date;
            """,
            (advisory["id"], advisory["id"], advisory["description"], embedding_list, advisory["assigner"], advisory["published_date"])
        )
        
        # Commit the transaction
        conn.commit()

        # Close the cursor and connection
        cursor.close()
        conn.close()

        print("Advisory and embedding stored successfully.")
    
    except Exception as e:
        print(f"Error storing advisory in the database: {e}")

# Main Flow: Read JSON -> Embed -> Store
def process_vulnerabilities(json_file_path):
    print("Starting the process...")
    advisories = read_vulnerabilities_from_json(json_file_path)  # Step 1: Read from JSON
    for advisory in advisories:
        embedding = embed_text(advisory["description"])  # Step 2: Create embedding for the description
        store_advisory_in_db(advisory, embedding)  # Step 3: Store advisory and embedding in database

# Step 4: Run the embedding process
if __name__ == '__main__':
    json_file_path = r'I:\IP-gitRepos\AI\KnowledgeBase\KnowledgeData.json'
    process_vulnerabilities(json_file_path)
