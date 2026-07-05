go build -o fabric ./cmd/fabric
sudo setcap 'cap_net_admin,cap_net_bind_service+ep' /home/user/Projects/IOA/fabric/fabric
scp fabric kodi:fabric
scp fabric gate.example.com:fabric
scp fabric relay.example.org:fabric
