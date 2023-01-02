use bytes::BytesMut;
use cryptnox_rs::utils::*;

#[test]
fn funky_padding() {
    for i in [
        "Hello world",
        "My name is John Doe",
        "Lorem ipsum dolor sit amet",
    ] {
        let data = BytesMut::from(i);
        println!("Data before padding: {:?}", data);
        let padded_data = {
            let mut padded = data.clone();
            pad_data(&mut padded);
            padded
        };
        println!("Padded data: {:?}", padded_data);
        let unpadded_data = remove_padding(&padded_data).unwrap();
        println!("Unpadded data: {:?}", unpadded_data);
        assert_eq!(data, unpadded_data);
    }
}
