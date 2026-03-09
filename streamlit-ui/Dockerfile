FROM python:3.12-slim

WORKDIR /app

COPY streamlit-ui/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt pandas

COPY streamlit-ui/app.py /app/app.py
COPY streamlit-ui/app_game_re.py /app/app_game_re.py

ENV UI_MODE=app_game_re

EXPOSE 8501

ENTRYPOINT ["sh", "-c", "streamlit run /app/${UI_MODE}.py --server.address=0.0.0.0 --server.port=8501"]
