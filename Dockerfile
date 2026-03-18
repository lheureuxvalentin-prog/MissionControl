FROM python:3.11-slim
RUN pip install flask flask-cors
WORKDIR /app
COPY app.py .
COPY index.html .
EXPOSE 5000
CMD ["python", "app.py"]
