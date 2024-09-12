# Referenced from Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com).
def ror(dword, bits):
    return (dword >> bits | dword << (32 - bits)) & 0xFFFFFFFF

def unicode(string, uppercase=True):
    result = ''
    if uppercase:
        string = string.upper()  
    for c in string:
        result += c + '\x00'  
    return result

def hash(module, function, bits=13):
    module_hash = 0
    function_hash = 0
    
    # Generate hash for the module name (convert to Unicode)
    for c in unicode(module + '\x00'):
        module_hash = ror(module_hash, bits)
        module_hash += ord(c)
    
    # Generate hash for the function name
    for c in str(function + '\x00'):
        function_hash = ror(function_hash, bits)
        function_hash += ord(c)
    
    final_hash = (module_hash + function_hash) & 0xFFFFFFFF
    
    print(f'[+] Hash: 0x{final_hash:08X} = {module.lower()}!{function}')
    return final_hash

def main():
    module = input("Enter the module name: ")
    function = input("Enter the function name: ")

    hash(module, function)

if __name__ == '__main__':
    main()