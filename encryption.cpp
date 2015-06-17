/*
Jeremy Doss
Main Project - Encryption Algorithm
CSCE 4550 - Introduction to Security
12/3/14
*/

#include <iostream>
#include <cstdlib>
#include <fstream>
#include <string>

#define MAX 16384

using namespace std;

//Global Declarations.
unsigned char message[MAX];
unsigned char key[16];
unsigned char matrix[MAX/16][4][4];
unsigned int msg_ctr;
ofstream output_log;

//Function Prototypes.
void encrypt(string);
void read_message(string);
void sub_cypher();
void pad();
void shift_rows();
void parity();
void mix_columns();
bool is_odd(unsigned char);
unsigned char rgf_multiply(unsigned char, int);

//Main program function.
int main() {
	string input;

	output_log.open("output.txt");
	
	output_log << "\n---------------------- A E S - E N C R Y P T I O N ----------------------\n" << endl;
	cout << "\n---------------------- A E S - E N C R Y P T I O N ----------------------\n" << endl;

	cout << "Options:\n1: 'run'\n2: 'exit'" << endl;

	//Main program loop.
	while(1) {
		cout << "Input:> ";
		cin >> input;

		if (input == "run" || input == "1") {
			cout << "Enter filename: ";
			cin >> input;

			//Initialize the encryption algorithm.
			encrypt(input);
		}

		else if (input == "exit" || input == "2") {
			output_log << "\n-----------------THANK YOU! Exiting encryption program..-----------------\n" << endl;
			cout << "\n-----------------THANK YOU! Exiting encryption program..-----------------\n" << endl;

			break;
		}

		else
			cout << "Error: Invalid command." << endl;
	}

	output_log.close();

	return 0;
}

void encrypt(string filename) {
	//Step 1: Preprocessing - Read and process the message from the input file.
	read_message(filename);

	//Step 2: Substitution - Use key.txt to encrypt the message.
	sub_cypher();

	//Step 3: Padding - Pad the encrypted message with 'A's.
	pad();

	//Step 4: ShiftRows - Perform a circular shift on each 4x4 matrix.
	shift_rows();

	//Step 5: Parity Bit - Alter each characters binary representation by altering the significant bit.
	parity();

	//Step 6: MixColumns - Multiply the circulant MDS matrix with each input column.
	mix_columns();

	cout << "Message finished encrypting! Thank you!" << endl;
	output_log << "\nMessage finished encrypting! Thank you!\n" << endl;
}

void read_message(string filename) {
	ifstream input;
	string line;

	input.open(filename.c_str());

	if (input.is_open()) {
		msg_ctr = 0;

		output_log << "\n----------------- Step 1: Preprocessing! ----------------" << endl;
		output_log << "\nInput Text:" << endl;

		while (getline(input, line)) {
			output_log << line;

			//Store each line in unsigned char array up to 80 characters.
			for (unsigned int i = 0; i < line.size(); i++) {
				if (i == 80) {
					output_log << "\nInput line length greater than 80 and was truncated." << endl;
					break;
				}

				if (line[i] >= 65 && line[i] <= 90) {
					message[msg_ctr] = line[i];
					msg_ctr++;
				}
			}
		}

		output_log << "\n\nOutput Text:" << endl;
		output_log << message << endl;

		input.close();
	}

	else {
		cout << "Error opening the input file!" << endl;
		cout << "Terminating program...\n" << endl;
		exit(0);
	}
}

void sub_cypher() {
	unsigned int m_val;
	unsigned int k_val;
	unsigned int e_val;
	ifstream input;
	string line;

	input.open("key.txt");

	if (input.is_open()) {
		output_log << "\n----------------- Step 2: Substitution! -----------------" << endl;
		output_log << "\nKey:" << endl;
		
		if (getline(input, line) && line.size() == 16) {
			for (int i = 0; i < 16; i++)
				key[i] = line[i];

			output_log << key << endl;
			output_log << "\nInput Text:\n" << message << endl;

		}

		else {
			cout << "Error! Incorrect encryption key size!" << endl;
			cout << "Terminating program...\n" << endl;
			return;
		}

		for (unsigned int i = 0; i < msg_ctr; i++) {
			m_val = message[i] - 65;
			k_val = key[i % 16] - 65;
			e_val = (m_val + k_val) % 26;

			message[i] = (unsigned char)(e_val + 65);
		}

		output_log << "\nOutput Text:" << endl;
		output_log << message << endl;

		input.close();
	}

	else {
		cout << "Error accessing the encryption key file!" << endl;
		cout << "Terminating program...\n" << endl;
		exit(0);
	}
}

void pad() {
	int count = 0;

	output_log << "\n-------------------- Step 3: Padding! -------------------" << endl;
	output_log << "\nInput:" << endl;

	//A loop for formatting the character array into a 4x4 look.
	for (unsigned int i = 0; i < msg_ctr; i++) {
		output_log << message[i];

		if ((i + 1) % 4 == 0)
			output_log << endl;

		if ((i + 1) % 16 == 0)
			output_log << endl;
	}

	//Add 'A's to make the correct message length.
	while (msg_ctr % 16 != 0) {
		message[msg_ctr] = 'A';
		msg_ctr++;
	}

	//Translate encrypted message string into an array of 4x4 unsigned characters.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++)
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				matrix[i][j][k] = message[count++];

	output_log << "\n\nOutput:" << endl;

	//A loop for outputting the 4x4 arrays.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				output_log << matrix[i][j][k];
			}
			output_log << endl;
		}
		output_log << endl;
	}
}

void shift_rows() {
	unsigned char temp;

	output_log << "\n------------------ Step 4: ShiftRows! -------------------" << endl;
	output_log << "\nInput:" << endl;

	//A loop for outputting the 4x4 arrays.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				output_log << matrix[i][j][k];
			}
			output_log << endl;
		}
		output_log << endl;
	}

	//Loop through and shift each 4x4 array.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		//Circular shift the second row by 1 column to the left.
		temp = matrix[i][1][0];
		matrix[i][1][0] = matrix[i][1][1];
		matrix[i][1][1] = matrix[i][1][2];
		matrix[i][1][2] = matrix[i][1][3];
		matrix[i][1][3] = temp;

		//Circular shift the third row by 2 columns to the left.
		temp = matrix[i][2][0];
		matrix[i][2][0] = matrix[i][2][2];
		matrix[i][2][2] = temp;

		temp = matrix[i][2][1];
		matrix[i][2][1] = matrix[i][2][3];
		matrix[i][2][3] = temp;

		//Circular shift the fourth row by 3 columns to the left.
		temp = matrix[i][3][0];
		matrix[i][3][0] = matrix[i][3][3];
		matrix[i][3][3] = matrix[i][3][2];
		matrix[i][3][2] = matrix[i][3][1];
		matrix[i][3][1] = temp;
	}

	output_log << "\n\nOutput:" << endl;

	//A loop for outputting the 4x4 arrays.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				output_log << matrix[i][j][k];
			}
			output_log << endl;
		}
		output_log << endl;
	}
}

void parity() {
	output_log << "\n------------------ Step 5: Parity Bit! ------------------" << endl;
	output_log << "\nInput:" << endl;

	//A loop for outputting the 4x4 arrays.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++)
				output_log << matrix[i][j][k];
			output_log << endl;
		}
	}

	//Loop through each character.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				//Check if even or odd amount of ones.
				if (is_odd(matrix[i][j][k])) {
					//Set significant bit to 1.
					matrix[i][j][k] |= 0x80;
				}
	}

	output_log << "\nOutput (in hexadecimal):" << endl;

	//A loop for outputting the 4x4 arrays.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++)
				output_log << hex << (int)matrix[i][j][k] << " ";
			output_log << endl;
		}
	}
}

void mix_columns() {
	unsigned char temp1, temp2, temp3;

	output_log << "\n------------------ Step 6: MixColumns! ------------------" << endl;
	output_log << "\nInput:" << endl;

	//A loop for outputting the 4x4 arrays.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++)
				output_log << hex << (int)matrix[i][j][k] << " ";
			output_log << endl;
		}
	}

	//Perform the MixColumns operations!
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			//Calculate a0.
			temp1 = matrix[i][0][j];
			matrix[i][0][j] = rgf_multiply(matrix[i][0][j], 2) ^ rgf_multiply(matrix[i][1][j], 3)
							^ matrix[i][2][j] ^ matrix[i][3][j];

			//Calculate a1.
			temp2 = matrix[i][1][j];
			matrix[i][1][j] = temp1 ^ rgf_multiply(matrix[i][1][j], 2) ^ rgf_multiply(matrix[i][2][j], 3)
							^ matrix[i][3][j];

			//Calculate a2.
			temp3 = matrix[i][2][j];
			matrix[i][2][j] = temp1 ^ temp2 ^ rgf_multiply(matrix[i][2][j], 2) ^ rgf_multiply(matrix[i][3][j], 3);

			//Calculate a3.
			matrix[i][3][j] = rgf_multiply(temp1, 3) ^ temp2 ^ temp3 ^ rgf_multiply(matrix[i][3][j], 2);
		}
	}

	output_log << "\nOutput (in hexadecimal):" << endl;

	//A loop for outputting the 4x4 arrays.
	for (unsigned int i = 0; i < (msg_ctr / 16); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++)
				output_log << hex << (int)matrix[i][j][k] << " ";
			output_log << endl;
		}
	}
}

bool is_odd(unsigned char value) {
	int bit_cnt = 0;

	while (value != 0) {
		if (value & 1)
			bit_cnt++;
		value >>= 1;
	}

	if (bit_cnt % 2 == 0)
		return false;
	else
		return true;
}

unsigned char rgf_multiply(unsigned char value, int rgf_val) {
	bool MSB = false;

	if (value & 0x80)
		MSB = true;

	switch (rgf_val) {
		case 2:
			value <<= 1;
			if (MSB) {
				value ^= 0x1b;
			}
			break;

		case 3:
			value = (value << 1) ^ value;
			if (MSB) {
				value ^= 0x1b;
			}
			break;

		default:
			break;
	}

	return value;
}