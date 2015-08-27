package uk.co.tstableford.hmac.challenge;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;


/**
 * This program generated a HMAC-SHA1 Signature based on a secret and given data.
 * It conforms somewhat to RFC 6238, except it is not time based. It could be used that way though.
 * It generates a 6 digit code from a 6 digit challenge.
 * 
 * Based upon http://www.lucadentella.it/en/totp-libreria-per-arduino/
 * Also based upon https://gist.github.com/ishikawa/88599
 */
public class Challenge {
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final int KEY_SIZE = 6;

	public static String calculateRFC6238HMAC(String data, String key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NumberFormatException
	{
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);

		long seed = Long.parseLong(data);
		byte _byteArray[] = new byte[8];
		_byteArray[0] = 0x00;
		_byteArray[1] = 0x00;
		_byteArray[2] = 0x00;
		_byteArray[3] = 0x00;
		_byteArray[4] = (byte)((seed >> 24) & 0xFF);
		_byteArray[5] = (byte)((seed >> 16) & 0xFF);
		_byteArray[6] = (byte)((seed >> 8) & 0XFF);
		_byteArray[7] = (byte)((seed & 0XFF));

		byte[] hash = mac.doFinal(_byteArray);

		int offset = hash[20 - 1] & 0xF; 
		int truncatedHash = 0;
		for (int j = 0; j < 4; ++j) {
			truncatedHash  |= ((hash[offset + j]) & 0xFF) << (8 * (3 - j));
		}

		// STEP 3, compute the OTP value
		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		return String.format("%06d", truncatedHash);
	}

	public static void main(String[] args) throws Exception {
		final String key;
		if(args.length > 0) {
			key = args[0];
			if(key.length() != 10) {
				JOptionPane.showMessageDialog(null, "Secret key length must be 10", "Error", JOptionPane.ERROR_MESSAGE);
				System.exit(0);
			}
		} else {
			JOptionPane.showMessageDialog(null, "No key specified as argument", "Error", JOptionPane.ERROR_MESSAGE);
			key = "";
			System.exit(0);
		}

		final JFrame fr = new JFrame();
		JPanel mainPanel = new JPanel();
		fr.add(mainPanel);

		final JTextField in = new JTextField(6);
		final JLabel result = new JLabel("Result: 000000");
		JButton generate = new JButton("Generate");

		mainPanel.add(in, BorderLayout.WEST);
		mainPanel.add(result, BorderLayout.CENTER);
		mainPanel.add(generate, BorderLayout.EAST);
		
		final Generator g = new Generator() {
			@Override
			public void generate() {
				if(in.getText().length() != KEY_SIZE) {
					JOptionPane.showMessageDialog(fr, "Input length is not " + KEY_SIZE, "Error", JOptionPane.ERROR_MESSAGE);
				} else {
					try {
						result.setText("Result: " + calculateRFC6238HMAC(in.getText(), key));
					} catch (NumberFormatException e2) {
						JOptionPane.showMessageDialog(fr, "Input is NaN", "Error", JOptionPane.ERROR_MESSAGE);
					} catch (InvalidKeyException e1) {
						JOptionPane.showMessageDialog(fr, "Invalid Secret Key", "Error", JOptionPane.ERROR_MESSAGE);
						e1.printStackTrace();
					} catch (SignatureException e1) {
						JOptionPane.showMessageDialog(fr, "Signature generation failure", "Error", JOptionPane.ERROR_MESSAGE);
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						JOptionPane.showMessageDialog(fr, "HMAC-SHA1 Unsupported", "Error", JOptionPane.ERROR_MESSAGE);
						e1.printStackTrace();
					}
				}
			}
		};

		generate.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				g.generate();
			}
		});
		
		in.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				g.generate();
			}
		});

		fr.setTitle("HMAC-SHA1 Challenger");
		fr.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		fr.setLocation(400, 400);

		fr.pack();
		fr.setVisible(true);
	}
	
	private interface Generator {
		public void generate();
	}
}