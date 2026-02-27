#!/bin/bash

# ═══════════════════════════════════════════════════════════════
# Auth Scanner - Multi-Protocole (Version Turbo v2)
# ═══════════════════════════════════════════════════════════════

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Vérification des arguments
if [ "$#" -lt 3 ]; then
    echo -e "${RED}[!] Usage: $0 <TARGET/CIDR> <USER> <PASS>${NC}"
    exit 1
fi

# Variables globales
TARGET=$1
USER=$2
PASS=$3
DOMAIN="INLANEFREIGHT.LOCAL"
PWNED_ONLY=false
THREADS=30 # Augmenté pour plus de vitesse
PORT_TIMEOUT=0.5 # Réduit à 0.5s pour accélérer le scan des ports fermés
AUTH_TIMEOUT=5

declare -A PORTS=( ["smb"]=445 ["ssh"]=22 ["ldap"]=389 ["ldaps"]=636 ["ftp"]=21 ["wmi"]=135 ["winrm"]=5985 ["winrms"]=5986 ["rdp"]=3389 ["vnc"]=5900 ["mssql"]=1433 ["nfs"]=2049 )
ALL_PROTOCOLS=("smb" "ssh" "rdp") # Réduit ici aux protocoles implémentés dans le case pour l'exemple
PROTOCOLS_TO_SCAN=("${ALL_PROTOCOLS[@]}")

TMP_FILE="/tmp/auth_scan_$$.txt"
> "$TMP_FILE"

# ═══════════════════════════════════════════════════════════════
# FONCTIONS CORE
# ═══════════════════════════════════════════════════════════════

check_port() {
    # Test ultra-rapide en bash natif
    timeout $PORT_TIMEOUT bash -c "</dev/tcp/$1/$2" 2>/dev/null
}

log_success() {
    # $1=Proto, $2=IP, $3=Port, $4=Message, $5=Commande de connexion
    echo -e "${GREEN}[✓] PWN3D! $1 sur $2:$3${NC}"
    echo -e "${MAGENTA}    ↳ Action : $5${NC}"
    echo "$1|$2|$3|$5" >> "$TMP_FILE"
}

log_failure() {
    [ "$PWNED_ONLY" = false ] && echo -e "${RED}[✗] $1 sur $2:$3 - Failed${NC}"
}

# Wrapper d'authentification unique pour parallélisation
worker() {
    local PROTO=$1
    local IP=$2
    local PORT=${PORTS[$PROTO]}
    local CMD=""
    local RESULT=""

    # Vérification rapide du port avant de lancer l'outil lourd
    if ! check_port "$IP" "$PORT"; then
        return
    fi

    case $PROTO in
        smb)
            CMD="smbclient \\\\\\\\$IP\\\\IPC\$ -U \"$DOMAIN\\\\$USER\"%\"$PASS\""
            RESULT=$(timeout $AUTH_TIMEOUT smbclient \\\\$IP\\IPC$ -U "$DOMAIN\\$USER"%"$PASS" -c "exit" 2>&1)
            if echo "$RESULT" | grep -qiE "NT_STATUS_SUCCESS|Success"; then 
                log_success "SMB" "$IP" "$PORT" "[+] Auth Success" "$CMD"
            else 
                log_failure "SMB" "$IP" "$PORT"
            fi
            ;;
        ssh)
            CMD="sshpass -p '$PASS' ssh -o StrictHostKeyChecking=no $USER@$IP"
            sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$AUTH_TIMEOUT -o BatchMode=yes "$USER"@"$IP" "exit" &>/dev/null
            if [ $? -eq 0 ]; then 
                log_success "SSH" "$IP" "$PORT" "[+] Auth Success" "$CMD"
            else 
                log_failure "SSH" "$IP" "$PORT"
            fi
            ;;
        rdp)
            CMD="xfreerdp /v:$IP /u:$USER /p:'$PASS' /d:$DOMAIN /cert:ignore /dynamic-resolution"
            RESULT=$(timeout $AUTH_TIMEOUT xfreerdp /v:"$IP" /u:"$USER" /p:"$PASS" /d:"$DOMAIN" /cert:ignore /auth-only 2>&1)
            if echo "$RESULT" | grep -qiE "success|authenticated"; then 
                log_success "RDP" "$IP" "$PORT" "[+] Auth Success" "$CMD"
            else 
                log_failure "RDP" "$IP" "$PORT"
            fi
            ;;
        # Ajoute les autres protocoles (WinRM, MSSQL...) en suivant ce modèle
    esac
}

get_ips() {
    if command -v nmap &> /dev/null; then
        nmap -sn "$1" -T4 -oG - | awk '/Up$/{print $2}'
    else
        # Fallback basique
        BASE=$(echo "$1" | cut -d'.' -f1-3)
        for i in {1..254}; do echo "$BASE.$i"; done
    fi
}

# ═══════════════════════════════════════════════════════════════
# EXECUTION
# ═══════════════════════════════════════════════════════════════

echo -e "${CYAN}[*] Génération de la liste des cibles...${NC}"
IP_LIST=$(get_ips "$TARGET")

echo -e "${CYAN}[*] Lancement du scan (Threads: $THREADS)...${NC}"

# Boucle de gestion des threads
for PROTO in "${PROTOCOLS_TO_SCAN[@]}"; do
    for IP in $IP_LIST; do
        # Lancer le worker en background
        worker "$PROTO" "$IP" &
        
        # Limiteur de threads natif bash
        while [[ $(jobs -r -p | wc -l) -ge $THREADS ]]; do
            wait -n
        done
    done
done

# Attendre la fin des derniers jobs
wait

echo -e "\n${CYAN}══════════════════════════════════════════════════════════${NC}"
if [ -s "$TMP_FILE" ]; then
    echo -e "${GREEN}✅ $(wc -l < "$TMP_FILE") succès trouvés !${NC}"
    echo -e "${YELLOW}Récapitulatif des commandes de connexion :${NC}"
    cat "$TMP_FILE" | awk -F'|' '{print "  " $4}'
else
    echo -e "${YELLOW}⚠️ Aucun accès trouvé.${NC}"
fi

rm -f "$TMP_FILE"