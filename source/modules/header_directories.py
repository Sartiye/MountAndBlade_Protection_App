import os

class Directory_Manager(dict):
    def __init__(self, **raw_directories):
        self.kwargs = dict()
        self.raw_directories = raw_directories
        for key, raw_directory in self.raw_directories.items():
            directory = Directory(self, key, raw_directory)
            setattr(self, key, directory)

    def format(self, **kwargs):
        self.kwargs.update(kwargs)

class Directory():
    def __init__(self, parent, key, raw_directory):
        self.parent = parent
        self.key = key
        self.kwargs = dict()
        string_parts = []
        for i, part in enumerate(raw_directory):
            if part == ".":
                string_parts.append(os.getcwd())
            elif part[0] == ".":
                string_parts.append(getattr(self.parent, part[1:]))
            else:
                string_parts.append(part)
        self.raw_string = os.path.join(*string_parts)

    def ensure_exists(self, path):
        os.makedirs(os.path.dirname(path), exist_ok = True)
        # If path ends like a file (e.g., has .log or .txt), create it
        if os.path.splitext(path)[1] and not os.path.exists(path):
            open(path, "a").close()

    def format(self, **kwargs):
        self.kwargs.update(kwargs)
        return self.string()

    def string(self):
        current_kwargs = self.kwargs.copy()
        current_kwargs.update(self.parent.kwargs)
        path = self.raw_string.format(**current_kwargs)
        self.ensure_exists(path)
        return path

    def __str__(self):
        return self.string()

    def __fspath__(self):
        return self.string()

    def basename(self):
        return os.path.basename(self)
    
    def __add__(self, other):
        return os.path.join(self, other)

    def __eq__(self, other):
        if type(other) == str:
            return self.string() == other
        else:
            return self == other
