#!/bin/bash

# Couleurs pour un output clean
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Vérification des arguments
if [ "$#" -lt 3 ]; then
    echo -e "${RED}[-] Usage: $0 <IP_Range> <USER> <PASSWORD> [DOMAIN]${NC}"
    echo -e "${BLUE}[*] Exemple: $0 172.16.5.0/24 svc_sql 'lucky7' INLANEFREIGHT.LOCAL${NC}"
    echo -e "${YELLOW}[!] IMPORTANT: Entourez le mot de passe de quotes simples si il contient des caractères spéciaux (ex: '!@#')${NC}"
    exit 1
fi

TARGET=$1
USER=$2
PASS=$3
DOMAIN=${4:-"INLANEFREIGHT.LOCAL"} # Domaine par défaut si non spécifié

# Vérification de nxc
if ! command -v nxc &> /dev/null; then
    echo -e "${RED}[-] nxc n'est pas installé ou pas dans le PATH.${NC}"
    exit 1
fi

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}   NetExec Auto-Enumeration Script${NC}"
echo -e "${BLUE}==================================================${NC}"
echo -e "${GREEN}Target :${NC} $TARGET"
echo -e "${GREEN}User   :${NC} $USER"
echo -e "${GREEN}Domain :${NC} $DOMAIN"
echo -e "${BLUE}==================================================${NC}"

# Fonction pour lancer nxc et filtrer le bruit
run_scan() {
    local PROTO=$1
    local EXTRA_ARGS=$2
    
    echo -e "\n${YELLOW}[★] Lancement du scan ${PROTO}...${NC}"
    
    # On lance nxc, on fusionne stderr et stdout, et on filtre les lignes inutiles
    nxc $PROTO $TARGET -u "$USER" -p "$PASS" -d "$DOMAIN" $EXTRA_ARGS 2>&1 | \
    grep -v -E "First time|Creating|Initializing|Copying|Running nxc|━|^\*$" | \
    grep -v "^$"
    
    # Si grep ne trouve rien, on affiche un message
    if [ ${PIPESTATUS[1]} -ne 0 ]; then
        # Cette partie est tricky avec les pipes, on fait simple :
        : 
    fi
}

# 1. WINRM
run_scan "winrm"

# 2. SMB (avec --shares)
run_scan "smb" "--shares"

# 3. MSSQL
run_scan "mssql"

# 4. RDP
run_scan "rdp"

echo -e "\n${BLUE}==================================================${NC}"
echo -e "${GREEN}[★] Énumération terminée.${NC}"
echo -e "${BLUE}==================================================${NC}"