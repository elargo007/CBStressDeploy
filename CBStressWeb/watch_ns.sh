cat <<'EOF' > watch_ns.sh
#!/bin/bash

i=1
while [ "$i" -le 60 ]
do
  ns=$(/usr/bin/dig NS james-bond-007.com +short | /usr/bin/sort | /usr/bin/paste -sd" " -)
  echo "[$(/bin/date)] $ns"

  if [[ "$ns" == *andronicus.ns.cloudflare.com.* && "$ns" == *linda.ns.cloudflare.com.* ]]; then
    echo "Nameservers updated!"
    exit 0
  fi

  /bin/sleep 120
  i=$((i+1))
done

echo "Timeout: Nameservers unchanged after 2 hours"
EOF
chmod +x watch_ns.sh
bash -x ./watch_ns.sh
