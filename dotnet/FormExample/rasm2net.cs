using r2pipe;
using System;

using System.Windows.Forms;

namespace R2Net {
	public class Rasm2 : Form {
		private IR2Pipe r2 = null;

		public string GetVersion() {
			return Cmd("?V").Trim();
		}

		public string Cmd(string cmd) {
			if (r2 != null) {
				return r2.RunCommand(cmd);
			}
			return "";
		}

		public string Disasm() {
			return r2.RunCommand("af;pdf").Trim();
		}

		public void Kill() {
			this.r2 = null;
		}

		private void Button_Click (object sender, EventArgs e) {
			var item = (string)arch.SelectedItem;
			Console.WriteLine(item);
			Application.Exit();
		}

		RichTextBox input;
		RichTextBox output;
		TextBox offs;
		ComboBox bits;
		ComboBox arch;

		private string assemble(string arch, string bits, string code) {
			string source = code.Replace("\n", ";");
			Cmd("s " + offs.Text + ";e asm.arch=" + arch + ";e asm.bits=" + bits);
			return Cmd("\"pa "+ source + "\"").Trim();
		}

		private string disasm(string arch, string bits, string code) {
			string hexpairs = code
				.Replace(" ","")
				.Replace(";", "")
				.Replace("\n","")
				.Replace("\r", "");
			Cmd("s " + offs.Text + ";e asm.arch=" + arch + ";e asm.bits=" + bits);
			return Cmd("\"pad " + hexpairs + "\"");
		}

		private void updateArchComboBox() {
			var archs = Cmd("e asm.arch=?q").Trim().Split('\n');
			Array.Sort(archs, StringComparer.InvariantCulture);
			foreach (var a in archs) {
				arch.Items.Add(a);
			}
		}

		private string pathToR2 = null;

		private void loadR2Pipe() {
			if (pathToR2 != null) {
				this.r2 = new R2Pipe("-", pathToR2);
			} else {
				this.r2 = new R2Pipe("-");
			}
		}

		public static bool IsWindows {
			get {
				int p = (int) Environment.OSVersion.Platform;
				return (p < 4);
			}
		}

		public Rasm2(string file) {
			loadR2Pipe();

			/* UI */
			this.Text = "rasm2.net";
			this.Width += 200;

			Button b = new Button ();
			b.Text = "Close";
			b.Left = this.Width - b.Width - 20;
			b.Top = this.Height - b.Height - 40;
			b.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
			b.Click += new EventHandler (Button_Click);
			Controls.Add (b);

			Label v = new Label ();
			v.Text = GetVersion();
			v.Left = 5;
			v.Top = this.Height - b.Height - 35;
			v.Width = this.Width;
			v.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
			Controls.Add (v);

			input = new RichTextBox();
			input.Anchor = (AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom);
			input.Top = 32;
			input.Height = (this.Height - input.Top) / 3;
			input.Width = this.Width - 20;
			input.Left = 5;
			Controls.Add (input);

			output = new RichTextBox();
			output.Anchor = (AnchorStyles.Bottom| AnchorStyles.Left | AnchorStyles.Right );
			output.Top = 32 + input.Height + 5 + 32;
			output.Height = (this.Height - output.Top) / 2;
			output.Width = this.Width - 20;
			output.Left = 5;
			Controls.Add (output);

			arch = new ComboBox();
			arch.DropDownStyle = ComboBoxStyle.DropDownList;
			arch.Top = 5;
			arch.Left = 5;
			updateArchComboBox();
			arch.SelectedItem = "x86";
			Controls.Add (arch);

			bits = new ComboBox();
			bits.DropDownStyle = ComboBoxStyle.DropDownList;
			bits.Top = 5;
			bits.Left = arch.Width + arch.Left + 10;
			bits.Items.Add("64");
			bits.Items.Add("32");
			bits.Items.Add("16");
			bits.Items.Add("8");
			bits.SelectedItem = "64";
			Controls.Add (bits);

			offs = new TextBox();
			offs.Text = "0";
			offs.Top = 5;
			offs.Left = bits.Width + bits.Left + 10;
			Controls.Add (offs);

			var ba = new Button ();
			ba.Text = "Assemble v";
			ba.Left = 50;
			ba.Top = input.Top + input.Height + 5;
			ba.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
			ba.Click += new EventHandler ((s, e) => {
				output.Text = assemble ((string)arch.SelectedItem,
					(string)bits.SelectedItem, input.Text);
			});
			Controls.Add (ba);

			var bd = new Button ();
			bd.Text = "Disasm ^";
			bd.Left = this.Width - bd.Width - 50;
			bd.Top = input.Top + input.Height + 5;
			bd.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
			bd.Click += new EventHandler ((s, e) => {
				input.Text = disasm ((string)arch.SelectedItem,
					(string)bits.SelectedItem, output.Text);
				//MessageBox.Show("disassemble");
			});
			Controls.Add (bd);

			var br = new Button ();
			br.Text = "radare2";
			br.Left = this.Width - br.Width - 20;
			br.Top = 5;
			br.Anchor = AnchorStyles.Top | AnchorStyles.Right;
			br.Click += new EventHandler ((s, e) => {
				if (IsWindows) {
					var fileDialog = new OpenFileDialog();
					fileDialog.Title = "Path to radare2.exe";
					fileDialog.Filter = "Windows Executables (*.exe)|*.exe";
					DialogResult result = fileDialog.ShowDialog(); // Show the dialog.
					if (result == DialogResult.OK) {
						pathToR2 = fileDialog.FileName;
						loadR2Pipe ();
						updateArchComboBox();
					}
					fileDialog = null;
				} else {
					if (this.r2 != null) {
						MessageBox.Show(GetVersion());
					} else {
						MessageBox.Show("Cannot find radare2 in PATH");
					}
				}
			});
			Controls.Add (br);
		}

		public static void Main(string[] args) {
			try {
				Rasm2 e = new Rasm2("-");
				Application.Run (e);
				e.Kill();
			} catch (Exception e) {
				MessageBox.Show(e.ToString());
			}
		}
	}
}
