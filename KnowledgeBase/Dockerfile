# # Use an official Python runtime as a parent image
# FROM python:3.9-slim

# # Set the working directory
# WORKDIR /usr/src/app

# # Copy the Python script and requirements into the container
# COPY Create_knowledgeBase.py .
# COPY requirements.txt .

# # Install the required Python packages
# RUN pip install -r requirements.txt

# # Run the Python script
# CMD ["python", "./Create_knowledgeBase.py"]

FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the KnowledgeBase files into the container
COPY KnowledgeData.json /app/
COPY Create_knowledgeBase.py /app/

COPY requirements.txt .
# Install any dependencies (if needed)
RUN pip install -r requirements.txt

# Run the script and then exit
CMD ["python", "Create_knowledgeBase.py"]
