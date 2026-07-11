import pefile

def extract_features(file):
    file.seek(0)  # IMPORTANT

    content = file.read()

    try:
        pe = pefile.PE(data=content)

        size = len(content)
        num_sections = len(pe.sections)

        entropy = 0
        for section in pe.sections:
            entropy += section.get_entropy()

        entropy = entropy / num_sections if num_sections > 0 else 0

    except:
        size = len(content)
        entropy = 0
        num_sections = 0

    return size, entropy, num_sections, content