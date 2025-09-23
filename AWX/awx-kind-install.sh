#!/usr/bin/env bash
#
# ----------------------------------------------------------------------------------
# IMPORTANT : Pour que ce script fonctionne, installez postgresql avec un compte 
# déjà configuré & une base créée et puis installez Docker et activez le !
# ----------------------------------------------------------------------------------
# Script Name: ./awx-kind-install.sh
# Author: Serdar AYSAN
# Email: contact@yucelsan.fr
# Date: 19-09-2025
# Description: Script d'installation de KIND AWX OPERATOR 2.19.1 VERSION AWX 24.6.1
# Cluster Kubernetes NameSpace {awx} KIND {Kubernetes IN Docker}
# Ce script a été testé sur Redhat 10 avec une base postgres déjà installée sur 
# le serveur et Docker activé. N'oubliez pas de modifier ce script avec vos données.
# ----------------------------------------------------------------------------------

### Ce script peut s'executer de n'importe où mais pour plus de sécurité déplacez vous dans le dossier /opt
cd /opt

### =====================[ PARAMS ]=====================
CLUSTER_NAME="${CLUSTER_NAME:-awx}"
AWX_NAMESPACE="${AWX_NAMESPACE:-awx}"
AWX_OPERATOR_VERSION="${AWX_OPERATOR_VERSION:-2.19.1}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.30.0}"

### NodePorts fixes côté cluster (ingress-nginx)
HTTP_NODEPORT="${HTTP_NODEPORT:-30080}"
HTTPS_NODEPORT="${HTTPS_NODEPORT:-30443}"

### Ports publiés sur l’hôte (via kind extraPortMappings)
HOST_HTTP="${HOST_HTTP:-8080}"
HOST_HTTPS="${HOST_HTTPS:-8443}"

### Hôte public (sera aussi mis en SAN du cert) : par défaut <IP>
IFACE="$(ip route show default | awk '/default/ {print $5}' | head -1)"
PUBLIC_IP="${PUBLIC_IP:-$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)}"
DOMAIN="${DOMAIN:-${PUBLIC_IP}.nip.io}"

### Admin AWX
AWX_ADMIN_USER="${AWX_ADMIN_USER:-admin}"
AWX_ADMIN_PASSWORD="${AWX_ADMIN_PASSWORD:-VOTRE-MOT-DE-PASSE-AWX}"

### External Postgres (activé par défaut)
EXTERNAL_POSTGRES="${EXTERNAL_POSTGRES:-true}" # --> Ici quand je mentionne postgres externe veut dire que votre base sera installée sur votre serveur (Hôte)
PGHOST="${PGHOST:-${PUBLIC_IP}}"
PGPORT="${PGPORT:-5432}"
PGDATABASE="${PGDATABASE:-nom-de-votre-base}"
PGUSER="${PGUSER:-adminpostgres}"
PGPASSWORD="${PGPASSWORD:-VOTRE-MOT-DE-PASSE-POSTGRES}"
PGSSLMODE="${PGSSLMODE:-prefer}"

### NGINX local en frontal
NGINX_CERT_DIR="${NGINX_CERT_DIR:-/etc/nginx/certs}"
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/etc/nginx/conf.d}"
NGINX_AWX_CONF="${NGINX_CONF_DIR}/awx.conf"
CATCHALL_CONF="${NGINX_CONF_DIR}/00-catchall.conf"
CERT_NAME="${CERT_NAME:-awx}" # -> /etc/nginx/certs/awx.crt/key

### Dossier des manifests générés
WORKDIR="${WORKDIR:-$(pwd)/awx-kind}"
mkdir -p "${WORKDIR}"
echo "[i] Manifests: ${WORKDIR}"
### ====================================================

### Téléchargement de kubectl...
command -v kubectl >/dev/null 2>&1 || {
  curl -fsSL -o /usr/local/bin/kubectl \
    "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x /usr/local/bin/kubectl
}

### Téléchargement de kind...
command -v helm >/dev/null 2>&1 || curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
if ! command -v kind >/dev/null 2>&1; then
  curl -fsSL -o /usr/local/bin/kind \
    "https://github.com/kubernetes-sigs/kind/releases/download/v0.23.0/kind-linux-amd64"
  chmod +x /usr/local/bin/kind
fi

### Cluster kind (ports exposés en loopback)
KIND_CFG="${WORKDIR}/kind-config.yaml"
cat > "${KIND_CFG}" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
  extraPortMappings:
  - containerPort: ${HTTP_NODEPORT}
    hostPort: ${HOST_HTTP}
    listenAddress: "127.0.0.1"
    protocol: TCP
  - containerPort: ${HTTPS_NODEPORT}
    hostPort: ${HOST_HTTPS}
    listenAddress: "127.0.0.1"
    protocol: TCP
EOF

### Création du cluster KIND AWX Si non existant.
if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "[+] kind create cluster --config ${KIND_CFG}"
  kind create cluster --config "${KIND_CFG}"
else
  echo "[=] Cluster kind '${CLUSTER_NAME}' déjà présent"
fi

### ingress-nginx (NodePort)
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null
helm repo update >/dev/null
if ! helm -n ingress-nginx list 2>/dev/null | grep -q ingress-nginx; then
  helm install ingress-nginx ingress-nginx/ingress-nginx \
    -n ingress-nginx --create-namespace \
    --set controller.kind=Deployment \
    --set controller.service.type=NodePort \
    --set controller.service.nodePorts.http=${HTTP_NODEPORT} \
    --set controller.service.nodePorts.https=${HTTPS_NODEPORT}
fi
kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=300s

### metrics-server (adapté kind) + vérification + alias
echo "[i] Déploiement de metrics-server…"
if ! kubectl -n kube-system get deploy metrics-server >/dev/null 2>&1; then
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
fi

### Patch des args pour kind (port 10250 + insecure TLS + address-types + node-status-port)
echo "[i] Patch metrics-server pour kind…"
kubectl -n kube-system patch deploy metrics-server --type='json' -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/args","value":[
    "--cert-dir=/tmp",
    "--secure-port=10250",
    "--kubelet-insecure-tls",
    "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
    "--kubelet-use-node-status-port",
    "--metric-resolution=15s"
  ]}
]' || true

### Redémarrage propre
kubectl -n kube-system rollout restart deploy/metrics-server
kubectl -n kube-system rollout status  deploy/metrics-server --timeout=180s || true

### Nettoyage des vieux ReplicaSets si le rollout reste coincé (best effort)
old_rs=$(kubectl -n kube-system get rs -l k8s-app=metrics-server \
  --sort-by=.metadata.creationTimestamp -o name 2>/dev/null | head -n -1 || true)
if [[ -n "${old_rs}" ]]; then
  echo "${old_rs}" | xargs -r kubectl -n kube-system delete
fi

### Attente disponibilité API metrics.k8s.io
echo "[i] Attente de l'API metrics.k8s.io…"
for i in {1..30}; do
  ok=$(kubectl get apiservice v1beta1.metrics.k8s.io -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null || echo "False")
  [[ "${ok}" == "True" ]] && break || sleep 5
done
kubectl get apiservice v1beta1.metrics.k8s.io -o wide || true

### Test rapide (best effort, n’échoue pas le script)
echo "[i] Test kubectl top (best effort)…"
kubectl top nodes || true
kubectl top pods -A --sort-by=cpu || true

### Namespace + Operator
kubectl get ns "${AWX_NAMESPACE}" >/dev/null 2>&1 || kubectl create ns "${AWX_NAMESPACE}"
kubectl apply -n "${AWX_NAMESPACE}" -f "https://github.com/ansible/awx-operator/config/default?ref=${AWX_OPERATOR_VERSION}"
kubectl -n "${AWX_NAMESPACE}" rollout status deploy/awx-operator-controller-manager --timeout=300s

### Cert TLS (self-signed) + Secret
mkdir -p "${NGINX_CERT_DIR}"
CRT="${NGINX_CERT_DIR}/${CERT_NAME}.crt"
KEY="${NGINX_CERT_DIR}/${CERT_NAME}.key"

cat > "${WORKDIR}/openssl-awx.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = awx.local
[v3_req]
subjectAltName = @alt
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[alt]
DNS.1 = awx.local
DNS.2 = ${DOMAIN}
EOF

### SI CERTIFICATS DEJA GENERES DESACTIVEZ LA LIGNE CI-DESSOUS (activez les commentaires #)
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout "${KEY}" -out "${CRT}" -config "${WORKDIR}/openssl-awx.cnf" >/dev/null

if [[ ! -f "${CRT}" || ! -f "${KEY}" ]]; then
  echo "ERREUR: Le certificat ${CRT} ou la clé ${KEY} est introuvable !"
  exit 1
fi

kubectl -n "${AWX_NAMESPACE}" delete secret awx-tls >/dev/null 2>&1 || true
kubectl -n "${AWX_NAMESPACE}" create secret tls awx-tls --cert="${CRT}" --key="${KEY}"

### Manifests demandés (générés dans ${WORKDIR})
### Admin password secret
cat > "${WORKDIR}/awx-admin-password.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: awx-admin-password
  namespace: ${AWX_NAMESPACE}
type: Opaque
stringData:
  password: "${AWX_ADMIN_PASSWORD}"
EOF

### External Postgres configuration (optionnel)
if [[ "${EXTERNAL_POSTGRES}" == "true" ]]; then
  for v in PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD; do
    [[ -n "${!v}" ]] || { echo "ERREUR: ${v} non défini alors que EXTERNAL_POSTGRES=true"; exit 1; }
  done
  cat > "${WORKDIR}/external-postgres-configuration.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: awx-external-postgres-configuration
  namespace: ${AWX_NAMESPACE}
type: Opaque
stringData:
  host: "${PGHOST}"
  port: "${PGPORT}"
  database: "${PGDATABASE}"
  username: "${PGUSER}"
  password: "${PGPASSWORD}"
  sslmode: "${PGSSLMODE}"
EOF
fi

### CR AWX (ingress_type:none car on gère l'Ingress à part via YAML)
cat > "${WORKDIR}/awx-instance.yaml" <<EOF
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: awx
  namespace: ${AWX_NAMESPACE}
spec:
  service_type: ClusterIP
  ingress_type: ingress
  hostname: ${DOMAIN}
  ingress_tls_secret: awx-tls
  create_preload_data: true
  admin_user: ${AWX_ADMIN_USER}
  admin_password_secret: awx-admin-password
  ${EXTERNAL_POSTGRES:+postgres_configuration_secret: awx-external-postgres-configuration}
  # (autres options possibles: resources, projects_persistence, etc.)
  replicas: 1
EOF

### Ingress principal (awx-ingress.yaml)
cat > "${WORKDIR}/awx-ingress.yaml" <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: awx-ingress
  namespace: ${AWX_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: awx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
      - awx.local
      - ${DOMAIN}
    secretName: awx-tls
  rules:
  - host: awx.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: awx-service
            port:
              number: 80
  - host: ${DOMAIN}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: awx-service
            port:
              number: 80
EOF

### Ingress supplémentaire (awx-extra-ingress.yaml) pour awx.local
cat > "${WORKDIR}/awx-extra-ingress.yaml" <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: awx-ingress-extra
  namespace: ${AWX_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: awx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts: [ "awx.local" ]
    secretName: awx-tls
  rules:
  - host: awx.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: awx-service
            port:
              number: 80
EOF

### Appliquer les manifests
kubectl apply -f "${WORKDIR}/awx-admin-password.yaml"
[[ "${EXTERNAL_POSTGRES}" == "true" ]] && kubectl apply -f "${WORKDIR}/external-postgres-configuration.yaml" || true
kubectl apply -f "${WORKDIR}/awx-instance.yaml"

echo "[~] Attente que le Service 'awx-service' existe…"
for i in {1..80}; do
  kubectl -n "${AWX_NAMESPACE}" get svc awx-service >/dev/null 2>&1 && break || sleep 5
done

kubectl apply -f "${WORKDIR}/awx-ingress.yaml"
kubectl apply -f "${WORKDIR}/awx-extra-ingress.yaml"

### Appliquer le volume ansible_nfs_pv & ansible_nfs_pvc pour monter les playbooks nfs
cat > "${WORKDIR}/awx-volume.yaml" <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ansible-nfs-pv
spec:
  capacity:
    storage: 80Gi
  accessModes: [ReadWriteMany]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  nfs:
    server: ${PUBLIC_IP}    # <-- IP de votre HÔTE
    path: /ansible          # <-- export NFS
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ansible-nfs-pvc
  namespace: awx
spec:
  accessModes: [ReadWriteMany]
  resources:
    requests:
      storage: 80Gi
  storageClassName: ""
  volumeName: ansible-nfs-pv
EOF

kubectl apply -f "${WORKDIR}/awx-volume.yaml"

kubectl -n awx patch awx awx --type merge -p '{
  "spec": {
    "projects_persistence": true,
    "projects_existing_claim": "ansible-nfs-pvc",
    "projects_storage_access_mode": "ReadWriteMany"
  }
}'

### NGINX local (frontend HTTPS -> kind:8443)
### Catch-all : si l’utilisateur tape l’IP, redirige vers le bon host
cat > "${CATCHALL_CONF}" <<EOF
server {
  listen 443 ssl default_server;
  listen [::]:443 ssl default_server;
  server_name _;
  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};
  return 308 https://${DOMAIN}\$request_uri;
}
EOF

### Vhost AWX
cat > "${NGINX_AWX_CONF}" <<EOF
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name ${DOMAIN} awx.local;

  ssl_certificate     ${CRT};
  ssl_certificate_key ${KEY};

  location / {
    proxy_pass https://127.0.0.1:${HOST_HTTPS};
    proxy_ssl_server_name on;
    proxy_ssl_verify off;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP \$remote_addr;
  }
}
EOF

### Firewall + SELinux + /etc/hosts
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-port=80/tcp  --permanent || true
  firewall-cmd --add-port=443/tcp --permanent || true
  firewall-cmd --reload || true
fi
command -v setsebool >/dev/null 2>&1 && setsebool -P httpd_can_network_connect 1 || true

grep -q "${PUBLIC_IP}  ${DOMAIN} awx.local" /etc/hosts || \
  echo "${PUBLIC_IP}  ${DOMAIN} awx.local" >> /etc/hosts

nginx -t && systemctl restart nginx

### === Pré-requis ===
echo "[INFO] Installation des paquets nécessaires..."
yum install -y epel-release

required_packages=("ansible" "git" "make" "nfs-utils")

### Vérifier chaque paquet
for pkg in "${required_packages[@]}"; do
    if ! yum list installed "$pkg" &>/dev/null; then
        echo "[INFO] Le paquet $pkg n'est pas installé, installation en cours..."
        yum install -y "$pkg"
    else
        echo "[INFO] Le paquet $pkg est déjà installé."
    fi
done

### Installer NFS si non présent
# if ! rpm -q nfs-utils >/dev/null 2>&1; then
#     yum install -y nfs-utils
#     systemctl enable --now nfs-server
# fi

### === Config NFS pour AWX ===
echo "[INFO] Configuration du partage NFS /ansible ..."

if [ ! -d /ansible ]; then
    # Créer le répertoire si nécessaire
    mkdir -p /ansible
    # Assigner les permissions
    chmod 755 /ansible
fi

### Activer le service NFS
systemctl enable --now nfs-server

### Créer l’export NFS
### Sauvegarde
cp /etc/exports /etc/exports.bak.$(date +%F)

### SI DEJA PRESENT, remplace toute ligne qui commence par /ansible
### sed -i -E 's#^/ansible\s+.*#/ansible 172.17.0.0/16(rw,sync,no_root_squash,no_subtree_check) 172.18.0.0/16(rw,sync,no_root_squash,no_subtree_check)#' /etc/exports

### Partage NFS : version test rapide (tous clients)
echo "/ansible *(rw,sync,no_root_squash,no_subtree_check)" >> /etc/exports

### SELinux (reco) : autoriser l'export en lecture et écriture
setsebool -P nfs_export_all_rw on

### Recharger la config NFS
exportfs -rav

### Autorisation Pare-feu
firewall-cmd --add-service=nfs --permanent
firewall-cmd --add-service=mountd --permanent
firewall-cmd --add-service=rpc-bind --permanent
firewall-cmd --reload

### Droits (AWX écrit en général via fsGroup 0)
chgrp -R 0 /ansible
chmod -R g+rwX /ansible
find /ansible -type d -exec chmod g+s {} \;

### TESTS SUR LE MONTAGE NFS
echo "[INFO] Exports actifs :"
exportfs -v | grep -A1 '^/ansible'
showmount -e "${PUBLIC_IP}"

echo
echo "================================================================"
echo " AWX prêt : https://${DOMAIN}"
echo " Admin user : ${AWX_ADMIN_USER}"
echo " Admin pass : (dans ${WORKDIR}/awx-admin-password.yaml) ou :"
echo " kubectl -n ${AWX_NAMESPACE} get secret awx-admin-password -o jsonpath='{.data.password}' | base64 -d; echo"
[[ "${EXTERNAL_POSTGRES}" == "true" ]] && echo " External PG: secret awx-external-postgres-configuration appliqué"
echo " Manifests générés dans : ${WORKDIR}"
echo "================================================================"
