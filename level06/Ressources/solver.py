import sys

input = sys.argv[1]
if len(input) <= 5:
    exit(1)
    
key = (ord(input[3]) ^ 4919) + 6221293

for i in range(len(input)):
    if ord(input[i]) < 32:
        exit(1) 
    key += (ord(input[i]) ^ key) % 1337
    
print(f"{key}")