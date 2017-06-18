package src;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.BevelBorder;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

/**
 * Simple GUI for representing the Paillier Cryptosystem homomorphic properties.
 * 
 * @version 12-03-2013
 */
public class GUI extends JPanel {

	/**
	 * 
	 */
	private static final long serialVersionUID = -229060049642162647L;
	public Controls control;
	public static JPanel textArea;
	public static JButton start;
	public static JButton processVoting;
	public AbstractTableModel EvoteTable;
	public static JTextArea screen;
	public static JPanel drawingArea;
	public static JLabel label;
	public static int row, col;
	public static boolean bool =  Boolean.FALSE;
	
	private static String[] columnNames = { "Voter Name",
			Candidates.CANDIDATE1.getName() + Candidates.CANDIDATE1.getExp(),
			Candidates.CANDIDATE2.getName() + Candidates.CANDIDATE2.getExp(),
			Candidates.CANDIDATE3.getName() + Candidates.CANDIDATE3.getExp(),
			Candidates.CANDIDATE4.getName() + Candidates.CANDIDATE4.getExp(),
			"Vote message to be encrypted", "Random Ri", "Encrypted Vote Ci" };
	private static Object[][] data = {
			{ "Voter 1", Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, new String(), new String(),
					new String() },
			{ "Voter 2", bool, bool, bool, bool, new String(), new String(),
					new String() },
			{ "Voter 3", bool, bool, bool, bool, new String(), new String(),
					new String() },
			{ "Voter 4", bool, bool, bool, bool, new String(), new String(),
					new String() },
			{ "Voter 5", bool, bool, bool, bool, new String(), new String(),
					new String() },
			{ "Voter 6", bool, bool, bool, bool, new String(), new String(),
					new String() },
			{ "Voter 7", bool, bool, bool, bool, new String(), new String(),
					new String() },
			{ "Voter 8", bool, bool, bool, bool, new String(), new String(),
					new String() } };

	/**
	 * Constructor invoke UIManager.LookAndFeelInfo for better GUI view .
	 * Initialises panels for controls and table.
	 */
	public GUI() {
		for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
			if ("Nimbus".equals(info.getName())) {
				try {
					UIManager.setLookAndFeel(info.getClassName());
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, e.getMessage(),
							"Error:ClassNotFoundException",
							JOptionPane.INFORMATION_MESSAGE);
				} catch (InstantiationException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, e.getMessage(),
							"Error:InstantiationException",
							JOptionPane.INFORMATION_MESSAGE);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, e.getMessage(),
							"Error:IllegalAccessException",
							JOptionPane.INFORMATION_MESSAGE);
				} catch (UnsupportedLookAndFeelException e) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(null, e.getMessage(),
							"Error:UnsupportedLookAndFeelException",
							JOptionPane.INFORMATION_MESSAGE);
				}
				break;
			}
		}
		setLayout(new BorderLayout());

		// panel for the table
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
		EmptyBorder eb = new EmptyBorder(5, 5, 5, 5);
		BevelBorder bb = new BevelBorder(BevelBorder.LOWERED);
		CompoundBorder cb = new CompoundBorder(eb, bb);
		mainPanel.setBorder(new CompoundBorder(cb, eb));
		// panel for the controls and text area
		JPanel pControls = new JPanel(new BorderLayout());
		pControls.setBorder(new EmptyBorder(1, 1, 1, 1));
		pControls.add(control = new Controls());
		mainPanel.add(new MyTableModel());
		mainPanel.add(pControls);
		add(mainPanel);

	}

	/**
	 * 
	 * @author peter
	 * 
	 */
	class MyTableModel extends JPanel {
		/**
		 * 
		 */
		private static final long serialVersionUID = 10872311100828632L;
		private JTable table;

		public MyTableModel() {

			setLayout(new BorderLayout());

			EvoteTable = new AbstractTableModel() {
				/**
				 * 
				 */
				private static final long serialVersionUID = -4645417069577376416L;

				@Override
				public int getColumnCount() {
					return columnNames.length;
				}

				@Override
				public int getRowCount() {
					return data.length;
				}

				@Override
				public String getColumnName(int col) {
					return columnNames[col];
				}

				@Override
				public Object getValueAt(int row, int col) {

					return data[row][col];
				}

				/**
				 * JTable uses this method to determine the default renderer/
				 * editor for each cell. If we didn't implement this method,
				 * then the last column would contain text ("true"/"false"),
				 * rather than a check box.
				 */
				@Override
				public Class<? extends Object> getColumnClass(int c) {
					return getValueAt(0, c).getClass();

				}

				/**
				 * Only first 4 entry with the check boxes are editable.
				 */
				@Override
				public boolean isCellEditable(int row, int col) {
					// Note that the data/cell address is constant,
					// no matter where the cell appears on screen.
					if (col > 4 || row == 8) {
						return false;
					} else {
						return true;
					}
				}

				/**
				 * This method updates the data model.
				 */
				@Override
				public void setValueAt(Object value, int row, int col) {

					if ((row == 8) && (col > 0 && col < 5)) {
						((Component) data[row][col]).setVisible(false);
						fireTableCellUpdated(row, col);

					} else {
						data[row][col] = value;
						fireTableCellUpdated(row, col);
					}
				}

			};

			table = new JTable(EvoteTable);
			table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
			table.setCellSelectionEnabled(true);
			table.setColumnSelectionAllowed(true);
			int lines = 2;
			table.setRowHeight(table.getRowHeight() * lines);// expand cells
			// resize the columns on demand
			for (int i = 0; i < columnNames.length; i++) {
				if (columnNames[i].endsWith("encrypted")) {
					TableColumn column = table.getColumn(columnNames[i]);
					column.setPreferredWidth(229);
				} else if (columnNames[i].endsWith("Ci")) {
					TableColumn column = table.getColumn(columnNames[i]);
					column.setPreferredWidth(205);
				} else if (columnNames[i].endsWith("Ri")) {

					TableColumn column = table.getColumn(columnNames[i]);
					column.setPreferredWidth(100);
				} else {
					TableColumn column = table.getColumn(columnNames[i]);
					column.setPreferredWidth(124);
				}
			}
			// Listener for row changes
			ListSelectionModel lsm = table.getSelectionModel();
			lsm.addListSelectionListener(new ListSelectionListener() {
				@Override
				public void valueChanged(ListSelectionEvent e) {
					ListSelectionModel sm = (ListSelectionModel) e.getSource();
					if (!sm.isSelectionEmpty()) {
						row = sm.getMinSelectionIndex();
					}
				}
			});

			// selection is now in terms of the underlying TableModel
			// Listener for column changes
			lsm = table.getColumnModel().getSelectionModel();
			lsm.addListSelectionListener(new ListSelectionListener() {
				@Override
				public void valueChanged(ListSelectionEvent e) {
					ListSelectionModel sm = (ListSelectionModel) e.getSource();
					if (!sm.isSelectionEmpty()) {
						col = sm.getMinSelectionIndex();
					}

					table.tableChanged(new TableModelEvent(EvoteTable));

				}
			});
			table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
			JScrollPane sp = new JScrollPane(table);
			sp.setBackground(Color.BLACK);
			sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			add(sp);
		}

	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(1185, 680);
	}

	@Override
	public Dimension getMaximumSize() {
		return new Dimension(1185, 680);
	}

	/**
	 * Class responsible for the JButtons and JTextArea with Listeners for the
	 * state change. From here make a call for encryption and decryption.
	 * 
	 * @author Peter Stefanov - NUIMaynooth
	 * 
	 */
	class Controls extends JPanel implements ActionListener, ItemListener {

		/**
		 * 
		 */
		private static final long serialVersionUID = -2296901791519955199L;

		public Controls() {
			setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
			setBorder(new EmptyBorder(1, 1, 1, 1));
			setBackground(Color.blue);

			JPanel t = new JPanel();
			t.setBorder(new EmptyBorder(5, 5, 5, 5));
			label = new JLabel();
			label.setLayout(new BorderLayout());
			t.add(label);
			t.setSize(1185, 50);
			add(t);
			JPanel p = new JPanel();
			start = new JButton("Start");
			start.addActionListener(this);
			p.add(start);
			processVoting = new JButton("ProcessVoting");
			processVoting.addActionListener(this);
			p.add(processVoting);
			add(p);

			textArea = new JPanel();
			screen = new JTextArea(17, 100);
			screen.setLineWrap(true);
			screen.setForeground(Color.blue);// set color for font
			screen.setBackground(Color.WHITE);// set background color
			// screen.setText("\n" + "Results from encryption and decryption");
			JScrollPane scrollingArea = new JScrollPane(screen);
			scrollingArea.setSize(15, 100);
			textArea.add(scrollingArea, BorderLayout.CENTER);
			add(textArea);

		}

		@Override
		public void actionPerformed(ActionEvent e) {
			PaillierCryptosystemUtil pcu = null;

			// get the index of the columns as needed
			int encryptCol = 0;
			int sumCol = 0;
			int rCol = 0;
			for (int j = 0; j < columnNames.length; j++) {
				if (columnNames[j].contains("Encrypted Vote Ci")) {
					encryptCol = j;
				}
				if (columnNames[j].contains("Vote message to be encrypted")) {
					sumCol = j;
				}
				if (columnNames[j].contains("Random Ri")) {
					rCol = j;
				}
			}
			if (e.getSource() == start) {
				screen.setText("");
				screen.append("\nNOTE:  This application has an introducing purpose, "
						+ " don't make conection with any real voting system.  The application is using"
						+ " base 10 numbers for distinguishing between candidates. Each voter can choose"
						+ " from null to four candidates. The sum of each voter's choice will be"
						+ " encrypted with a unique random number r, such that the produced ciphertext"
						+ " for the same plaintext(messages) will be different. Place your choice by"
						+ " clicking on check box under each candiadte. After encryption of individual"
						+ " voter's choices the product of them modulus n^2(component of Paillier Public key)"
						+ " will be decrypted to obtain the initial tally, which is in decimal form,to a"
						+ " number with the base chosen at the beginning of the election.\n In other words"
						+ " encrypted tally of the all votes decrypts to the sum of all plain votes.");
			} else if (e.getSource() == processVoting) {
				try {
					// Only once create an instance of PaillierCryptosystemUtil.
					// Actual encryption/decryption starts with pressing some of
					// buttons.
					pcu = new PaillierCryptosystemUtil();
				} catch (NoSuchAlgorithmException exception) {
					exception.printStackTrace();
					JOptionPane.showMessageDialog(null, exception.getMessage(),
							"Error:NoSuchAlgorithmException",
							JOptionPane.INFORMATION_MESSAGE);
				}
				BigInteger votes[] = getVoteSum();// get the sum of each voter
				BigInteger[] cipherText = new BigInteger[votes.length];
				try {
					// get the encrypted messages in String array
					// doing encryption one at the time for each vote
					// using the same Public key , but different r.
					// see doEncrypt(int[]a).
					cipherText = pcu.doEncrypt(votes);
				} catch (Exception e1) {
					e1.printStackTrace();

				}

				// populate the table with the data from encryption,with sum
				// and r for each encryption where the #Col is the correct
				// column index for the appropriate column.
				String[] rRandom = pcu.getrRandom();
				int i = 0;
				while (i < votes.length) {
					EvoteTable.setValueAt(rRandom[i], i, rCol);
					EvoteTable.setValueAt(cipherText[i], i, encryptCol);
					EvoteTable.setValueAt(" m = " + String.valueOf(votes[i]),
							i, sumCol);
					i++;
				}

				BigInteger sumVoteMessages = BigInteger.ZERO;
				String showExpression = " (";
				for (int j = 0; j < votes.length; j++) {
					// calculate the sum of all m and update into the table
					sumVoteMessages = sumVoteMessages.add(votes[j]);
					if (j < votes.length - 2) {
						showExpression += cipherText[j].toString() + " * ";
					} else {
						showExpression += cipherText[j].toString();// remove the
																	// last *
					}
				}
				// reverse the sumVoteMessages to get the tally
				String sTally = getTally(sumVoteMessages);
				BigInteger productCiperTexts = getProduct(cipherText);

				// display the sum of messages and reversed tally
				label.setText("Sum of all voter's messages  =  "
						+ String.valueOf(sumVoteMessages)
						+ "  ==>   tally (reversed sum) = " + sTally);
				String nModulus = pcu.getKeyComponent("n");// get the n needed
															// for tallying
				BigInteger n = new BigInteger(nModulus);
				BigInteger n2 = n.multiply(n);
				screen.append("\n\nN = " + nModulus + "\n");
				screen.append("\nN^2 = " + n2 + "\n");
				// construct the expression showing tallying of all products
				// mod n^2 , and calculate and show the result
				BigInteger tally = productCiperTexts.mod(n2);
				screen.append("\n(PRODUCT OF ALL:Ci) MOD N^2 ="
						+ showExpression + ") mod " + n2 + " = " + tally + "\n");

				BigInteger decryptedTally = BigInteger.ZERO;
				try {
					decryptedTally = pcu.doDecrypt(tally);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				String tallyExpression = retrieveTally(decryptedTally);
				screen.append("\nDECRYPRION (" + tally + ") = "
						+ decryptedTally + " = " + tallyExpression);
				EvoteTable.fireTableDataChanged();// refresh/update the table
			}
		}

		/**
		 * Returned the reversed sum of the voters messages. The reverse order
		 * of the sum matched(each entry) to the numbers of votes for each
		 * candidate - simple tally.
		 * 
		 * @return the simple tally in reverse order - String
		 */
		public String getTally(BigInteger sumVoteMessages) {
			String source = sumVoteMessages.toString();
			String reversedSum = "";
			for (String part : source.split(" ")) {
				reversedSum = new StringBuffer(part).reverse().toString();
			}
			return reversedSum;
		}

		@Override
		public void itemStateChanged(ItemEvent arg0) {

		}

		@Override
		public Dimension getPreferredSize() {
			return new Dimension(1185, 525);
		}

		@Override
		public Dimension getMaximumSize() {
			return new Dimension(1185, 525);
		}

	}

	/**
	 * Method to chop down the result in order to get the vote results. This
	 * application used base 10. To concatenate the resulting output in one
	 * string. Needs only to be displayed at the screen.
	 * 
	 * @param decryptedTally
	 * @return results - String
	 */
	public String retrieveTally(BigInteger decryptedTally) {

		if (decryptedTally.equals(BigInteger.ZERO))
			return "No candidates selected";

		String s = " ";
		String w = "\n\nOr each candidate has:\n\n";
		List<Integer> list = new ArrayList<Integer>();
		BigInteger ten = new BigInteger("10");
		while (!decryptedTally.equals(BigInteger.ZERO)) {
			list.add(0, decryptedTally.mod(ten).intValue());
			decryptedTally = decryptedTally.divide(ten);
		}
		// using enum class to get the String representation(the base) for each
		// candidate
		Candidates[] candidates = Candidates.values();
		for (int i = 0; i < list.size(); i++) {
			if (i < list.size() - 1) {
				s = s + list.get(i).toString() + "*"
						+ candidates[list.size() - i - 1].getExp() + " + ";
				w = w + list.get(i).toString() + " vote(s) for "
						+ candidates[list.size() - i - 1].getName() + "\n";
			} else {
				s = s + list.get(i).toString() + "*"
						+ candidates[list.size() - i - 1].getExp();
				w = w + list.get(i).toString() + " vote(s) for "
						+ candidates[list.size() - i - 1].getName();
			}
		}
		return s + w;
	}

	/**
	 * Method for calculating the product of all ciphertexts .
	 * 
	 * @param cipherText
	 *            - BigInteger[]
	 * @return product - BigInteger
	 */
	public BigInteger getProduct(BigInteger[] cipherText) {

		BigInteger mul = BigInteger.ONE;
		for (int i = 0; i < cipherText.length; ++i) {
			mul = mul.multiply(cipherText[i]);
		}
		return mul;

	}

	/**
	 * Method to get all the data that is true - the choice of each voter, and
	 * to calculate the sum for each voter that need to be encrypted. The base
	 * ten valu for each candidate is retrieved from Candidates enum class. Easy
	 * for maintains if you want to change the base for the candidates.
	 * 
	 * @return votes - BigInteger[] array
	 * 
	 */
	public BigInteger[] getVoteSum() {

		Candidates[] candidates = Candidates.values();
		BigInteger[] votes = new BigInteger[data.length];
		// initialise each entry in array with value zero
		for (int y = 0; y < votes.length; y++)
			votes[y] = BigInteger.ZERO;
		for (int i = 0; i < data.length; i++) {
			for (int j = 0; j < columnNames.length; j++) {
				if (data[i][j].equals(true)) {
					if (j == 1) {
						votes[i] = candidates[0].getValue();
					}
					if (j == 2) {
						votes[i] = votes[i].add(candidates[1].getValue());
					}
					if (j == 3) {
						votes[i] = votes[i].add(candidates[2].getValue());
					}
					if (j == 4) {
						votes[i] = votes[i].add(candidates[3].getValue());
					}
				}
			}
		}

		return votes;
	}

	/**
	 * Create the GUI and show it. For thread safety, this method should be
	 * invoked from the event-dispatching thread.
	 */
	public static void createAndShowGUI() {
		// Create and set up the window.
		JFrame frame = new JFrame("Paillier Cryptosystem for E-Voting");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		// Create and set up the content pane.
		GUI newContentPane = new GUI();
		newContentPane.setOpaque(true); // content panes must be opaque
		frame.setContentPane(newContentPane);
		frame.pack();
		frame.setVisible(true);

	}

	public static void main(String[] args) {
		// Schedule a job for the event-dispatching thread:
		// creating and showing this application's GUI.
		javax.swing.SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				createAndShowGUI();
			}
		});

	}
}