#!/bin/bash

APK_DIR="/apks"
OUTPUT_DIR="/results"

# Assicuriamoci che l'immagine di SEBASTiAn sia disponibile
# docker pull talossec/sebastian:latest

mkdir -p "$OUTPUT_DIR/SEBASTiAn" "$OUTPUT_DIR/APKHunt" "$OUTPUT_DIR/Trueseeing"

start_time=$(date +%s%3N)

for apk in "$APK_DIR"/*.apk; do

  if [ ! -f "$apk" ]; then continue; fi
  base_name=$(basename "$apk" .apk)

  echo "[*] Start Trueseeing Analysis: $base_name"
  trueseeing -eqc 'as;gj' "$apk" > "$OUTPUT_DIR/Trueseeing/$base_name.json"

  # echo "[*] Start APKHUNT Analysis: $base_name"
  # go run /app/APKHunt/apkhunt.go -p "$apk" -l
  # find /app /apks -maxdepth 1 -name "*.txt" -exec mv {} "$OUTPUT_DIR/APKHunt/" \;
  # echo "[*] Start SEBASTiAn Analysis: $base_name"
  # # Copia l'APK nel volume condiviso accessibile da SEBASTiAn
  # cp "$apk" /shared/"$base_name.apk"

  # # Lancia SEBASTiAn usando il volume condiviso (il demone Docker è raggiunto
  # # tramite il socket montato: -v /var/run/docker.sock:/var/run/docker.sock)
  # docker run --rm \
  #   --platform linux/amd64 \
  #   -v shared_workspace_vol:/workdir \
  #   talossec/sebastian:latest  -t 5000\
  #   -gr "$base_name.apk"

  # find /shared/ -type f \( -name "*.json" -o -name "*.txt" -o -name "*.pdf" \) \
  # -exec mv {} "$OUTPUT_DIR/SEBASTiAn/" \;
  # python3 AddToCSV.py "$base_name"

done

end_time=$(date +%s%3N)
elapsed_time=$((end_time - start_time))
elapsed_seconds=$((elapsed_time / 1000))
elapsed_milliseconds=$((elapsed_time % 1000))
printf "[*] Total analysis completed in %d.%03ds\n" "$elapsed_seconds" "$elapsed_milliseconds"
echo "[*] Analisi Completata per tutti i file!"
