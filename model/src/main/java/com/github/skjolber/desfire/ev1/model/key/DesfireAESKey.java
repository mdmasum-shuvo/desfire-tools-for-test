package com.github.skjolber.desfire.ev1.model.key;

import android.os.Parcel;
import android.os.Parcelable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class DesfireAESKey extends DesfireKey {

	public static DesfireAESKey defaultVersionNull = new DesfireAESKey("AES null", 0x01, new byte[16]);
	public static DesfireAESKey defaultVersion42 = new DesfireAESKey("Default AES", 00, new byte[]{(byte) 0xE3, (byte) 0xB7, 0x15, 0x58, (byte) 0xE2, (byte) 0xBF, 0x79, 0x1C, 0x5D, 0x03, (byte) 0xF5, 0x05, 0x36, 0x7B, 0x38, (byte) 0xD4});
	
	public DesfireAESKey(String name, int version, byte[] value) {
		this();
		
		this.name = name;

		this.version = version;
		
		if(value.length != 16) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}

	public DesfireAESKey() {
		this.type = DesfireKeyType.AES;
	}

	public void setValue(byte[] value) {
		if(value != null && value.length != 16) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}
	
	public void read(DataInputStream in) throws IOException {
		super.read(in);
		
		value = new byte[16];
		in.readFully(value);
	}

	@Override
	public void write(DataOutputStream dest) throws IOException {
		super.write(dest);
		
		dest.write(value);
	}

    public static final Parcelable.Creator<DesfireAESKey> CREATOR
            = new Parcelable.Creator<DesfireAESKey>() {
        public DesfireAESKey createFromParcel(Parcel in) {
            return new DesfireAESKey(in);
        }

        public DesfireAESKey[] newArray(int size) {
            return new DesfireAESKey[size];
        }
    };

    private DesfireAESKey(Parcel in) {
        readFromParcel(in);
    }
}
