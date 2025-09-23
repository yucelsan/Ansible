#!/usr/bin/env bash
#
# --------------------------------------------------------------------------------------
# Script Name: ./awx-kind-uninstall.sh
# Author: Serdar AYSAN
# Email: contact@yucelsan.fr
# Date: 19-09-2025
# Description: Script de désinstallation de KIND AWX OPERATOR 2.19.1 VERSION AWX 24.6.1
# Cluster Kubernetes NameSpace {awx} KIND {Kubernetes IN Docker}
# Ce script a déjà été testé sur Redhat 10
# --------------------------------------------------------------------------------------

CLUSTER_NAME="${CLUSTER_NAME:-awx}"
AWX_NAMESPACE="${AWX_NAMESPACE:-awx}"
AWX_OPERATOR_VERSION="${AWX_OPERATOR_VERSION:-2.19.1}"
WORKDIR="${WORKDIR:-$(pwd)/awx-kind}"
NGINX_CERT_DIR="${NGINX_CERT_DIR:-/etc/nginx/certs}"
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/etc/nginx/conf.d}"
NGINX_AWX_CONF="${NGINX_CONF_DIR}/awx.conf"
CATCHALL_CONF="${NGINX_CONF_DIR}/00-catchall.conf"

echo "[+] Suppression des Ingress/Secrets/CR (si présents)"

kubectl delete -f "${WORKDIR}/awx-extra-ingress.yaml" --ignore-not-found=true || true
kubectl delete -f "${WORKDIR}/awx-ingress.yaml"       --ignore-not-found=true || true
kubectl delete -f "${WORKDIR}/awx-instance.yaml"      --ignore-not-found=true || true

kubectl delete -f "${WORKDIR}/awx-admin-password.yaml" --ignore-not-found=true || true
kubectl -n "${AWX_NAMESPACE}" delete secret awx-tls --ignore-not-found=true || true
kubectl delete -f "${WORKDIR}/external-postgres-configuration.yaml" --ignore-not-found=true || true

echo "[+] AWX Operator & namespace"

kubectl -n "${AWX_NAMESPACE}" delete -f "https://github.com/ansible/awx-operator/config/default?ref=${AWX_OPERATOR_VERSION}" --ignore-not-found=true || true
kubectl delete ns "${AWX_NAMESPACE}" --ignore-not-found=true || true

echo "[+] Ingress NGINX"
helm uninstall ingress-nginx -n ingress-nginx || true
kubectl delete ns ingress-nginx --ignore-not-found=true || true

echo "[+] Cluster kind"
kind delete cluster --name "${CLUSTER_NAME}" || true

kubectl delete crd awxs.awx.ansible.com \
  awxbackups.awx.ansible.com \
  awxrestores.awx.ansible.com \
  --ignore-not-found=true || true

kubectl config delete-context "kind-${CLUSTER_NAME}" 2>/dev/null || true
kubectl config delete-cluster "kind-${CLUSTER_NAME}" 2>/dev/null || true
kubectl config unset "users.kind-${CLUSTER_NAME}" 2>/dev/null || true

echo "[+] NGINX cleanup"

# on supprime les confs vhosts pour la partie nginx

rm -f "${NGINX_AWX_CONF}" "${CATCHALL_CONF}" || true

# on ne supprime pas les certificats self-signed pour les réutiliser
# find "${NGINX_CERT_DIR}" -maxdepth 1 -type f -name 'awx.*' -exec rm -f {} \; || true

# on redémarre nginx avec une conf vierge

nginx -t && systemctl reload nginx || true

# on remet le fichier /etc/hosts vierge

echo "[+] /etc/hosts cleanup (nip.io / awx.local)"
sed -i.bak '/nip\.io/d;/awx\.local/d' /etc/hosts || true

echo "[OK] Ingress NGINX supprimé"
echo "[OK] Cluster kind supprimé: ${CLUSTER_NAME}"
echo "[OK] Confs NGINX nettoyées (certificats conservés)"
echo "[OK] Entrées /etc/hosts nettoyées"
echo "[OK] Désinstallation complète de AWX KIND Kubernetes IN Docker."
