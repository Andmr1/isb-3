import logging


def write_bin(path: str, variable: bytes) -> None:
    """
    Function writes binary variable to txt file
    :param path: Location where variable be saved
    :param variable: variable we need to save
    """
    try:
        with open(path, 'wb') as key_file:
            key_file.write(variable)
        logging.info(f'key has been written into {path}!')
    except OSError as err:
        logging.warning(f'{err} Error during writing into {path}!')
