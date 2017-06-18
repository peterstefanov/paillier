package paillierPrototype;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.UIManager.LookAndFeelInfo;
import javax.swing.text.JTextComponent;

import java.util.*;
import java.io.*;
import java.math.*;

/**
 * Simple prototype outlining the  Paillier Cryptosystem with few  <br>
 * examples of homomorphic properties which  scheme preserves<br>
 * @version 3 (24/11/2012)
 * 
 */

public class GUIPaillier extends JFrame

{
	private static final long serialVersionUID = -2941460502747314396L;
	PaillierAlgorithm paillier = new PaillierAlgorithm();
	private JTextField PtextField;
	private JTextField QtextField;
	private JPanel buttonpanel_dialog;
	private JButton buttons_dialog[];
	private JButton encrypt;
	private JButton decrypt;
	private JButton generate;
	private JButton homomorphism;
	private String names1[] = { "Open", "Save" };
	private static JTextArea screen;
	private Container container;
	private ArrayList<String> array_List;
	private JTextField NtextField;
	private JTextField MtextField;
	private JTextField M1textField;
	private JTextField GtextField;
	private JTextField CtextField;
	private JTextField C1textField;
	private JTextField DtextField;
	private JTextField D1textField;
	private JTextField StextField;
	ButtonHandler handler = new ButtonHandler();
	private String[] description = { "0", "4", "8", "16", "32", "56", "64",
			"128", "192", "256", "384", "512", "1024", "2048" };
	private int count = 0;

	/**
	 * Constructor
	 */
	public GUIPaillier() {// constructor

		// Instantiation of objects
		array_List = new ArrayList<String>();
		container = getContentPane();
		// container.setLayout(new FlowLayout( FlowLayout.CENTER, 5,5));
		buttonpanel_dialog = new JPanel();
		generate = new JButton("generate");
		encrypt = new JButton("encrypt");
		decrypt = new JButton("decrypt");
		homomorphism = new JButton("homomorphism");
		homomorphism.addActionListener(handler);

		// open and save buttons
		buttons_dialog = new JButton[names1.length];
		createOpenSaveButtons();
		createTextArea();
		createSetUpParametersPanel();
		try {
			for (LookAndFeelInfo info : UIManager
					.getInstalledLookAndFeels()) {
				System.out.println(info.getName());
				if ("Nimbus".equals(info.getName())) {
					UIManager.setLookAndFeel(info.getClassName());
					break;
				}
			}
		} catch (UnsupportedLookAndFeelException e) {
			// handle exception
		} catch (ClassNotFoundException e) {
			// handle exception
		} catch (InstantiationException e) {
			// handle exception
		} catch (IllegalAccessException e) {
			// handle exception
		}
		// set title for the frame
		setTitle("Paillier Cryptosystem");
		pack();
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setVisible(true);

	}

	/**
	 * <ol>
	 * This method set up the the view of the GUI
	 * </ol>
	 */
	private void createSetUpParametersPanel() {
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

		PtextField = new JTextField(20);
		QtextField = new JTextField(20);
		NtextField = new JTextField(38);
		GtextField = new JTextField(38);
		CtextField = new JTextField(38);
		C1textField = new JTextField(38);
		DtextField = new JTextField(30);
		D1textField = new JTextField(30);
		MtextField = new JTextField(30);
		M1textField = new JTextField(30);

		StextField = new JTextField(5);

		setKeySizeViewPanel(mainPanel);
		setPQViewPanel(mainPanel);
		setTextDescriptionLabel(mainPanel);
		setNViewPanel(mainPanel);
		setGViewPanel(mainPanel);
		setMViewPanel(mainPanel);
		setM1ViewPanel(mainPanel);
		setCViewPanel(mainPanel);
		setC1ViewPanel(mainPanel);
		setDViewPanel(mainPanel);
		setD1ViewPanel(mainPanel);
		container.add(mainPanel, BorderLayout.WEST);
	}

	/**
	 * Panel for decrypted plaintext 1<br>
	 * 
	 * @param mainPanel
	 */
	private void setD1ViewPanel(JPanel mainPanel) {
		JPanel d1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
		d1.add(new JLabel("Decrypted m1 =   "));
		d1.add(D1textField);
		d1.add(new JLabel("m1 = L(c1^lambda mod n^2)mu mod n"));
		mainPanel.add(d1);

	}

	/**
	 * Panel for ciphertext 1<br>
	 * 
	 * @param mainPanel
	 */
	private void setC1ViewPanel(JPanel mainPanel) {
		JPanel c = new JPanel(new FlowLayout(FlowLayout.LEFT));
		c.add(new JLabel("Ciphertext c1 =    "));
		c.add(C1textField);
		c.add(new JLabel("c1 = g^m1 * r1^n mod n^2"));
		mainPanel.add(c);

	}

	/**
	 * Panel for plaintext 1<br>
	 * 
	 * @param mainPanel
	 */
	private void setM1ViewPanel(JPanel mainPanel) {
		JPanel m1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
		m1.add(new JLabel("Plaintext m1 =     "));
		m1.add(M1textField);
		m1.add(new JLabel(
				"m1 < n                                                     "));
		mainPanel.add(m1);

	}

	/**
	 * create Decryption panel<br>
	 * 
	 * @param mainPanel
	 */
	private void setDViewPanel(JPanel mainPanel) {
		JPanel d = new JPanel(new FlowLayout(FlowLayout.LEFT));
		d.add(new JLabel("Decrypted m =     "));
		d.add(DtextField);
		d.add(new JLabel("m = L(c^lambda mod n^2)mu mod n"));
		// Button for decrypt cipher text c
		decrypt.addActionListener(handler);
		d.add(decrypt);
		mainPanel.add(d);

	}

	/**
	 * Panel for ciphertext<br>
	 * 
	 * @param mainPanel
	 */
	private void setCViewPanel(JPanel mainPanel) {
		JPanel c = new JPanel(new FlowLayout(FlowLayout.LEFT));
		c.add(new JLabel("Ciphertext c =      "));
		c.add(CtextField);
		c.add(new JLabel("c = g^m * r^n mod n^2"));
		mainPanel.add(c);
	}

	/**
	 * Panel for plaintext input<br>
	 * 
	 * @param mainPanel
	 */
	private void setMViewPanel(JPanel mainPanel) {
		JPanel m = new JPanel(new FlowLayout(FlowLayout.LEFT));
		m.add(new JLabel("Plaintext m =       "));
		m.add(MtextField);
		m.add(new JLabel(
				"m < n                                                     "));
		// Button for encrypt message m
		encrypt.addActionListener(handler);
		m.add(encrypt);
		mainPanel.add(m);
	}

	/**
	 * Set panel for g <br>
	 * 
	 * @param mainPanel
	 */
	private void setGViewPanel(JPanel mainPanel) {
		JPanel g = new JPanel(new FlowLayout(FlowLayout.LEFT));
		g.add(new JLabel("Generate g =       "));
		g.add(GtextField);
		g.add(new JLabel("g = (an + 1)b^n mod n^2"));
		mainPanel.add(g);
	}

	/**
	 * Set panel for n <br>
	 * 
	 * @param mainPanel
	 */
	private void setNViewPanel(JPanel mainPanel) {
		JPanel n = new JPanel(new FlowLayout(FlowLayout.LEFT));
		n.add(new JLabel("Compute n = p*q "));
		n.add(NtextField);
		mainPanel.add(n);
	}

	/**
	 * Set text description panel with just label for p,q <br>
	 * 
	 * @param mainPanel
	 */
	private void setTextDescriptionLabel(JPanel mainPanel) {
		JPanel t = new JPanel();
		t.add(new JLabel(" p and q are distinct prime numbers "));
		mainPanel.add(t);
	}

	/**
	 * Set p and q panel<br>
	 * 
	 * @param mainPanel
	 */
	private void setPQViewPanel(JPanel mainPanel) {
		// JPanel for p q
		JPanel pq = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JLabel p = new JLabel("p = ");
		pq.add(p);
		pq.add(PtextField);
		pq.add(new JLabel("q = "));
		pq.add(QtextField);

		// Button for generating random p,q and calculate g and n
		generate.addActionListener(handler);
		pq.add(generate);
		mainPanel.add(pq);
	}

	/**
	 * Set key size panel<br>
	 * 
	 * @param mainPanel
	 */
	private void setKeySizeViewPanel(JPanel mainPanel) {
		JPanel s = new JPanel();
		JLabel keySize = new JLabel("keySize(in bits) = ");
		s.add(keySize);
		final JComboBox c = new JComboBox();
		for (int i = 0; i < 14; i++)
			c.addItem(description[count++]);

		c.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				StextField.setText((String) ((JComboBox) e.getSource())
						.getSelectedItem());
			}
		});

		s.add(c);
		mainPanel.add(s);
	}

	/**
	 * 
	 */
	private void createTextArea() {
		screen = new JTextArea(30, 30);
		screen.setForeground(Color.gray);// set color for font
		screen.setBackground(Color.WHITE);// set background color
		screen.setText("\n" + "Results from encryption and decryption");
		JScrollPane scrollingArea = new JScrollPane(screen);
		scrollingArea.setSize(30, 30);
		container.add(scrollingArea, BorderLayout.CENTER);
	}

	/**
	 * Method for create save open buttons<br>
	 */
	private void createOpenSaveButtons() {
		for (int i = 0; i < names1.length; i++) {
			buttons_dialog[i] = new JButton(names1[i]);
			buttons_dialog[i].addActionListener(handler);
			buttonpanel_dialog.add(buttons_dialog[i], BorderLayout.NORTH);
		}
		container.add(buttonpanel_dialog, BorderLayout.SOUTH);
	}

	/**
	 * method for reading the file and to store in arrayList <br>
	 * getContent
	 * 
	 * @param aFile
	 * 
	 */
	public void getContent(File aFile) {

		BufferedReader input = null;
		try {
			array_List.clear();// just in case if been opened wrong file
			input = new BufferedReader(new FileReader(aFile));
			String line = null;
			while ((line = input.readLine()) != null) {
				if (line.trim().length() != 0)// skip blank lines

					array_List.add(line);

			}

		} catch (FileNotFoundException ex) {
			ex.printStackTrace();
		} catch (IOException ex) {
			ex.printStackTrace();
		} finally {
			try {
				if (input != null) {
					input.close();
				}
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}

	}

	/**
	 * method to write into the TextArea in from there we can store in the file
	 * the same content(we can edit the content before to store)<br>
	 * setContent
	 * 
	 * @param newFile
	 */
	public void setContent(File newFile) {
		try {

			BufferedWriter bufferedWriter = null;

			bufferedWriter = new BufferedWriter(new FileWriter(newFile));

			if (bufferedWriter != null) {
				bufferedWriter.write(screen.getText());
				bufferedWriter.close();
			}

		} catch (IOException e) {

		}
	}

	/**
	 * Class for handle the even which occurs after clicking on any buttons also
	 * we can add more event to be handle in future,all what we need is just to
	 * implement and add the new button in separate file with existing one class<br>
	 * actionPerformed
	 * 
	 * 
	 * 
	 */

	public class ButtonHandler implements ActionListener {

		BigInteger d;// don't have KeyFactory yet so need to declare d in order
						// to store first decryption result

		@Override
		public void actionPerformed(ActionEvent event) {
			if (event.getSource() == generate) {// when pressed generates p,q,g
												// and n
				// Store the current system time
				final long time = System.currentTimeMillis();
				// get the key size from the user
				int keyBitLength = Integer.parseInt(StextField.getText());
				paillier.initialize(keyBitLength);// passing the bitLength of
													// key
				paillier.generateKeyPair();// call method to generate the keys
				long time1 = System.currentTimeMillis() - time;

				// get the keys
				BigInteger n = paillier.getN();
				BigInteger p = paillier.getP();
				BigInteger q = paillier.getQ();
				BigInteger g = paillier.getG();
				// print at the screen
				QtextField.setText(q.toString());
				PtextField.setText(p.toString());
				NtextField.setText(n.toString());
				GtextField.setText(g.toString());
				// double check that the condition for p and q are
				// satisfied:gcd(pq,(p-1)(q-1))=1
				boolean check = isGcd.isGcdOne(PtextField.getText(),
						QtextField.getText());
				if (check == true) {
					screen.append("\n\n" + "p = " + p.toString() + "\n"
							+ "q = " + q.toString() + "\n" + "n = "
							+ n.toString() + "\n" + "g = " + g.toString());
					screen.append("\n\n"
							+ "P and Q are satisfied gcd(pq,(p-1)(q-1))=1"
							+ "\n" + "Took " + String.valueOf(time1)
							+ "mls to generate p,q and g.");
				} else {// try different numbers NO ACTION
					screen.append("\n\n"
							+ "P and Q are NOT satisfied gcd(pq,(p-1)(q-1))=1"
							+ "\n" + "TRY WITH ANOTHER P AND Q ");
				}
			} else if (event.getSource() == encrypt) {// when you hit encrypt

				BigInteger m = new BigInteger(MtextField.getText());
				BigInteger m1 = new BigInteger(M1textField.getText());
				// call the encrypt method
				final long timec = System.currentTimeMillis();
				BigInteger c, c1;
				BigInteger r, r1;

				try {
					c = paillier.encrypt(m);
					((JTextComponent) CtextField).setText(c.toString());
					d = paillier.decrypt(c);// need to call first decription
											// here to store the result
					r = paillier.getR();
					c1 = paillier.encrypt(m1);
					((JTextComponent) C1textField).setText(c1.toString());
					r1 = paillier.getR();
					long time1c = System.currentTimeMillis() - timec;
					screen.append("\n\n" + "m = " + m.toString() + "\n"
							+ "m1 = " + m1.toString());
					screen.append("\n\n" + "r = " + r.toString() + "\n"
							+ "r1 = " + r1.toString());
					screen.append("\n\n" + "c = " + c.toString() + "\n"
							+ "c1 = " + c1.toString() + "\n" + "Took "
							+ String.valueOf(time1c)
							+ "mls to encrypt messages m and m1.");
				} catch (Exception e1) {
					e1.printStackTrace();
				}

			} else if (event.getSource() == decrypt) {
				// call the decrypt method
				final long timed = System.currentTimeMillis();
				try {

					BigInteger c1 = paillier.getC();
					BigInteger d1 = paillier.decrypt(c1);
					((JTextComponent) DtextField).setText(d.toString());
					((JTextComponent) D1textField).setText(d1.toString());
					long time1d = System.currentTimeMillis() - timed;
					screen.append("\n\n" + "m = " + d.toString() + "\n"
							+ "m1 = " + d1.toString() + "\n" + "Took "
							+ String.valueOf(time1d)
							+ "mls to decrypt ciphertexts c and c1.");
				} catch (Exception e) {
					e.printStackTrace();
				}
				// crate an instance of popup factory to provoke
				PopupFactory factory = PopupFactory.getSharedInstance();

				int x = 970;
				int y = 510;
				// position where to pop up button - "homomorphic"
				final Popup popup = factory.getPopup(container, homomorphism,
						x, y);
				popup.show();
				ActionListener hider = new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						popup.hide();
					}
				};
				// Hide popup in 10 seconds
				Timer timer = new Timer(10000, hider);
				timer.start();

			} else if (event.getSource() == homomorphism) {
				homomorphicFrame();// invoke method to show homomorphism

			} else if (event.getSource() == buttons_dialog[0]) {// button open

				String cwd = System.getProperty("user.dir");
				final JFileChooser jfc = new JFileChooser(cwd);

				if (jfc.showOpenDialog(container) != JFileChooser.APPROVE_OPTION)
					return;
				File f = jfc.getSelectedFile();
				// calling getContents method to read and store the chosen file
				getContent(f);

				// display content of chosen file on the screen (TextArea)
				// reading backwards from the file
				for (int i = array_List.size() - 1; i >= 0; i--) {
					screen.insert("  \n " + array_List.get(i), 0);
				}

			}

			else if (event.getSource() == buttons_dialog[1]) {// save button
				String c = System.getProperty("user.dir");
				final JFileChooser jfc1 = new JFileChooser(c);
				if (jfc1.showSaveDialog(container) != JFileChooser.APPROVE_OPTION)
					return;
				File file = jfc1.getSelectedFile();
				setContent(file);

			}

		}

	}

	/**
	 * 
	 * 
	 * Create new frame to outline the homomorphism preserve in the scheme<br>
	 * Test 1. homomorphic properties -> D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod
	 * n <br>
	 * Test 2. homomorphic properties -> D(E(m)g^m1 mod n^2) = (m1 + m2) mod n <br>
	 * 
	 * @param Not
	 *            used
	 */
	public void homomorphicFrame() {
		JFrame frame = new JFrame("Homomorphic addition of plaintexts");
		// main JPanel to handle the layout , not using internal JFrame
		JPanel main = new JPanel();
		main.setLayout(new BoxLayout(main, BoxLayout.Y_AXIS));

		// Panel for conditions
		JPanel condition = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JLabel cond = new JLabel("To preserve homomorphism (m + m1) < n");
		cond.setForeground(Color.RED);// set color for font
		condition.add(cond);
		main.add(condition);

		// Panel for the ciphertexts
		JPanel cipher = new JPanel();
		JPanel cc1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
		cc1.add(new JLabel("c = "));
		JTextField ctextField = new JTextField(20);
		ctextField.setText(CtextField.getText());
		JTextField c1textField = new JTextField(20);
		c1textField.setText(C1textField.getText());
		cc1.add(ctextField);
		cc1.add(new JLabel("c1 =  "));
		cc1.add(c1textField);
		cipher.add(cc1);
		main.add(cipher);

		// Panel for the plaintexts
		JPanel plaintext = new JPanel();
		JPanel mm = new JPanel(new FlowLayout(FlowLayout.LEFT));
		mm.add(new JLabel("m = "));
		JTextField mtextField = new JTextField(20);
		mtextField.setText(MtextField.getText());
		JTextField m1textField = new JTextField(20);
		m1textField.setText(M1textField.getText());
		mm.add(mtextField);
		mm.add(new JLabel("m1 = "));
		mm.add(m1textField);
		plaintext.add(mm);
		main.add(plaintext);

		// Panel for the D(E(m,r)*E(m1,r1) mod n^2)
		JPanel example = new JPanel();
		JPanel productPlaintexts = new JPanel(new FlowLayout(FlowLayout.LEFT));
		// E(m,r)*E(m1,r1) mod n^2
		BigInteger product_cc = new BigInteger(CtextField.getText()).multiply(
				new BigInteger(C1textField.getText())).mod(
				paillier.getNSquare());
		// D(E(m,r)*E(m1,r1) mod n^2)
		productPlaintexts.add(new JLabel("D(E(m,r)*E(m1,r1) mod n^2) = "));
		JTextField decryptProducttextField = new JTextField(20);
		BigInteger decrypt = paillier.decrypt(product_cc);
		decryptProducttextField.setText(decrypt.toString());
		productPlaintexts.add(decryptProducttextField);
		// m + m1
		BigInteger sum_mm1 = new BigInteger(MtextField.getText())
				.add(new BigInteger(M1textField.getText()));
		// (m + m1) mod n^ =
		productPlaintexts.add(new JLabel("(m + m1) mod n = "));
		JTextField sum_mod = new JTextField(20);
		BigInteger mod = sum_mm1.mod(paillier.getN());
		sum_mod.setText(mod.toString());
		productPlaintexts.add(sum_mod);
		example.add(productPlaintexts);
		main.add(example);

		// Panel for descriptions
		JPanel descriptions1 = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JLabel desc = new JLabel(
				"Product of two ciphertext will decrypt to the sum of their corresponding plaintexts. D(E(m,r)*E(m1,r1) mod n^2) = (m + m1) mod n ");
		desc.setForeground(Color.RED);// set color for font
		descriptions1.add(desc);
		main.add(descriptions1);

		// Panel for D(E(m)g^m1 mod n^2) = (m1 + m2) mod n
		JPanel example2 = new JPanel();
		JPanel exponent = new JPanel(new FlowLayout(FlowLayout.LEFT));
		exponent.add(new JLabel("        D(E(m)g^m1 mod n^2)  = "));
		JTextField expotextField = new JTextField(20);
		// E(m)g^m1 mod n^2
		BigInteger expo_Em = (new BigInteger(CtextField.getText()).modPow(
				BigInteger.ONE, paillier.getNSquare()).multiply(paillier.getG()
				.modPow(new BigInteger(M1textField.getText()),
						paillier.getNSquare()))).mod(paillier.getNSquare());
		expotextField.setText((paillier.decrypt(expo_Em)).toString());
		exponent.add(expotextField);
		// (m + m1) mod n
		exponent.add(new JLabel("(m + m1) mod n = "));
		JTextField product = new JTextField(20);
		BigInteger prod = new BigInteger(MtextField.getText()).add(
				new BigInteger(M1textField.getText())).mod(paillier.getN());
		product.setText(prod.toString());
		exponent.add(product);
		example2.add(exponent);
		main.add(example2);

		// Panel for descriptions
		JPanel descriptions2 = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JLabel desc2 = new JLabel(
				"Product of a ciphertext with a plaintext raising g will decrypt to the sum of the corresponding plaintexts.  D(E(m)g^m1 mod n^2) = (m1 + m2) mod n ");
		desc2.setForeground(Color.RED);// set color for font
		descriptions2.add(desc2);
		main.add(descriptions2);
		frame.add(main);
		frame.pack();
		frame.setVisible(true);
	}

	/**
	 * @param args
	 *            Not used
	 */
	public static void main(String args[]) {
		new GUIPaillier();


	}

}
