import os
import argparse
import sys

def build_tree(root, ignore_directories=None, ignore_hidden=True):
    if ignore_directories is None:
        ignore_directories = ['.git']
    tree = []
    def traverse(dir, prefix):
        entries = sorted(os.listdir(dir))
        if ignore_hidden:
            entries = [e for e in entries if not e.startswith('.')]
        entries = [e for e in entries if os.path.isfile(os.path.join(dir, e)) or os.path.isdir(os.path.join(dir, e))]
        entries = [e for e in entries if os.path.basename(os.path.join(dir, e)) not in ignore_directories]
        for i, entry in enumerate(entries):
            is_last = i == len(entries) - 1
            full_path = os.path.join(dir, entry)
            if os.path.isdir(full_path):
                tree.append(f"{prefix}{'└── ' if is_last else '├── '}{entry}/")
                traverse(full_path, f"{prefix}{'    ' if is_last else '│    '}")
            else:
                tree.append(f"{prefix}{'└── ' if is_last else '├── '}{entry}")
    traverse(root, "")
    return '\n'.join(tree)

def main():
    parser = argparse.ArgumentParser(description='Scan a folder repository and gather source files into a single Markdown file.')
    parser.add_argument('input_dir', help='Input directory to scan.')
    parser.add_argument('output_file', help='Output Markdown file.')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input_dir)
    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} is not a valid directory.")
        sys.exit(1)

    output_file = args.output_file

    # List of directories to ignore
    ignore_directories = ['.git', 'dist', 'node_modules', 'assets', 'screenshots', 'img']

    # List of allowed file extensions
    allowed_extensions = ['.txt', '.py', '.md', '.html', '.css', '.js', '.json', '.yaml', '.yml', '.xml', '.csv', '.go', '.c', '.h', 'Dockerfile', '.sh', 'Makefile']

    # Generate project tree
    tree = build_tree(input_dir, ignore_directories=ignore_directories)

    # Collect files and their content
    files = []
    for root, dirs, filenames in os.walk(input_dir):
        # Skip ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_directories and not d.startswith('.')]
        for filename in filenames:
            if filename.startswith('.'):
                continue  # Skip hidden files
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, input_dir)
            # Check file extension
            _, ext = os.path.splitext(filename)
            if ext.lower() not in allowed_extensions:
                continue  # Skip files with unsupported extensions
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Escape special characters for Markdown
                    content = content.replace('\\', '\\\\')\
                                     .replace('`', '\\`')\
                                     .replace('*', '\\*')\
                                     .replace('_', '\\_')\
                                     .replace('{', '\\{')\
                                     .replace('}', '\\}')\
                                     .replace('[', '\\[')\
                                     .replace(']', '\\]')\
                                     .replace('(', '\\(')\
                                     .replace(')', '\\)')\
                                     .replace('#', '\\#')\
                                     .replace('+', '\\+')\
                                     .replace('-', '\\-')\
                                     .replace('.', '\\.')\
                                     .replace('!', '\\!')
                    files.append((rel_path, content))
            except Exception as e:
                if args.verbose:
                    print(f"Error reading {file_path}: {e}")

    # Write to Markdown file
    with open(output_file, 'w', encoding='utf-8') as md:
        # Write project tree
        md.write("## Project Structure\n")
        md.write("```\n")
        md.write(tree)
        md.write("\n```\n")

        # Write files content
        for file_path, content in files:
            md.write(f"\n## {file_path}\n")
            md.write("```\n")
            md.write(content)
            md.write("\n```\n")
            md.write("____\n")

    if args.verbose:
        print(f"Successfully generated {output_file}")

if __name__ == '__main__':
    main()
