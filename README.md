Deploying the GOAD Range

Full sequence to rebuild the `GOAD` range from `REDPILLS-range`.

### 1. Generate the topology
cd ~/REDPILLS-range
bailey gen \
  --spec goad-daniel.bailey.spec.yml \
  --catalog goad-daniel.bailey.catalog.yml \
  --seed 20260911 > artifacts/topology.20260911.yml

### 2. Render the provisioning config
bailey render \
  --from artifacts/topology.20260911.yml \
  --catalog goad-daniel.bailey.catalog.yml \
  --mode provisioning \
  --out artifacts/

### 3. Push config and redeploy (1-2+ hours)
ludus range config set -r GOAD -f artifacts/range-config.provisioning.yml
ludus range rm -r GOAD
ludus range deploy -r GOAD
ludus range logs -f -r GOAD

### 4. Post-deploy setup (not captured in the base spec — must be redone after every reset)

**SSH + domain admin on dragonstone:**
ansible-playbook -i shared-goad-inventory.ini leg_ssh_setup.yml -f 1

**Fix kali's DNS:**
ssh kali@10.25.10.18
echo "nameserver 10.25.10.12" | sudo tee /etc/resolv.conf

**Deploy the phishing poller :**
ansible-playbook -i shared-goad-inventory.ini phishing_poller_setup.yml -f 1

### Optional: reset flags/CVEs via scenario_gen.py
python3 scenario_gen.py \
  artifacts/range-config.provisioning.yml \
  --seed 1234 \
  --range-prefix 10.25 \
  --percent 50 \
  --vulns-per-host 1
  
Then run the generated `scenario.yml` 
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES \
ansible-playbook -i scenario-inventory.ini scenario.yml -f 1