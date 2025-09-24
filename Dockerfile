# Use Python slim image
FROM python:3.11-slim

# Install system dependencies for RDP and network tools
RUN apt-get update && apt-get install -y \
    freerdp2-x11 \
    xrdp \
    openssh-client \
    iputils-ping \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Set Python unbuffered mode
ENV PYTHONUNBUFFERED=1

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server code
COPY windows_admin_server.py .

# Create log directory
RUN mkdir -p /app/logs

# Create non-root user
RUN useradd -m -u 1000 mcpuser && \
    chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Run the server
CMD ["python", "windows_admin_server.py"]