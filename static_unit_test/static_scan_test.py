import unittest
import subprocess
import difflib
import os

class TestKubiScan(unittest.TestCase):

    def setUp(self):
        """Set up the environment for each test."""
        self.current_directory = os.getcwd()

        #CHANGE combined.yaml to the json/yaml file you created for the static scan.
        self.json_file_path = os.path.join(self.current_directory, "combined.yaml")
        print(f"Setting up for test in {self.current_directory}")

    def tearDown(self):
        """Clean up after each test."""
        print("Tearing down test environment...")

    def run_command(self, cmd):
        """Helper function to run shell commands and capture output."""
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout, result.stderr

    def filter_output(self, output):
        """Helper function to filter out non-essential lines from the output."""
        filtered_lines = [line for line in output.splitlines() 
                          if "KubiScan version" not in line 
                          and "Author" not in line 
                          and "Using kube config file" not in line]
        return "\n".join(filtered_lines)

    def compare_outputs(self, output1, output2):
        """Helper function to compare two outputs and show differences."""
        output1_filtered = self.filter_output(output1)
        output2_filtered = self.filter_output(output2)

        diff = difflib.unified_diff(
            output1_filtered.splitlines(), output2_filtered.splitlines(), lineterm='', 
            fromfile='Regular API Scan', tofile='Static JSON Scan'
        )
        diff_output = '\n'.join(diff)
        if diff_output:
            print(f"Differences found:\n{diff_output}")
        return diff_output

    def run_and_compare_scans(self, regular_args, static_args, description):
        """Helper function to run and compare regular API scan with static JSON scan."""
        regular_cmd = ["python3", "./KubiScan.py"] + regular_args
        static_cmd = ["python3", "./KubiScan.py", "-f", self.json_file_path] + static_args

        regular_output, regular_error = self.run_command(regular_cmd)
        static_output, static_error = self.run_command(static_cmd)

        # Ensure both commands ran without errors
        self.assertEqual(regular_error, '', f"Error in regular API scan: {regular_error}")
        self.assertEqual(static_error, '', f"Error in static JSON scan: {static_error}")

        # Compare outputs and assert no differences
        diff = self.compare_outputs(regular_output, static_output)
        self.assertEqual(diff, '', f"Outputs differ between regular API scan and static JSON scan for {description}.")
        print(f"✅ Test passed: {description} scan comparison is identical.")

    def test_risky_roles(self):
        self.run_and_compare_scans(["-rr"], ["-rr"], "Risky Roles")

    def test_risky_clusterroles(self):
        self.run_and_compare_scans(["-rcr"], ["-rcr"], "Risky ClusterRoles")

    def test_risky_any_roles(self):
        self.run_and_compare_scans(["-rar"], ["-rar"], "Risky Roles and ClusterRoles")

    def test_risky_rolebindings(self):
        self.run_and_compare_scans(["-rb"], ["-rb"], "Risky RoleBindings")

    def test_risky_clusterrolebindings(self):
        self.run_and_compare_scans(["-rcb"], ["-rcb"], "Risky ClusterRoleBindings")

    def test_risky_any_rolebindings(self):
        self.run_and_compare_scans(["-rab"], ["-rab"], "Risky RoleBindings and ClusterRoleBindings")

    def test_risky_subjects(self):
        self.run_and_compare_scans(["-rs"], ["-rs"], "Risky Subjects")

    def test_risky_pods(self):
        self.run_and_compare_scans(["-rp"], ["-rp"], "Risky Pods")


    #def test_risky_pods(self): ## There is a bug in KubiScan need to fix.
        #self.run_and_compare_scans(["-rp" , "-d"], ["-rp", "-d"], "Risky Pods Deep!")

    #def test_privleged_pods(self):
        #self.run_and_compare_scans(["-pp"], ["-pp"], "Privleged Pods")

    def test_risky_rolebindings_namespace(self):
        self.run_and_compare_scans(["-rb", "-ns", "kube-system"], ["-rb", "-ns", "kube-system"], "Risky RoleBindings with namespace!")

    def test_risky_all(self):
        self.run_and_compare_scans(["-a"], ["-a"], "All risky Roles\ClusterRoles, RoleBindings\ClusterRoleBindings, users and pods\containers.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
